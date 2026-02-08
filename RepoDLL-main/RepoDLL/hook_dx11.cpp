#include "pch.h"

#include "hook_dx11.h"

#include <d3d11.h>
#include <dxgi.h>
#include <dxgi1_2.h>

#include "MinHook.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>

#include "mono_bridge.h"
#include "ui.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ESP 开关（供 mono_bridge 等引用）
bool g_esp_enabled = false;
// Overlay 状态（供 mono_bridge 等引用）
bool g_overlay_disabled = false;

namespace {
using PresentFn = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT);
using ResizeBuffersFn = HRESULT(__stdcall*)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);

PresentFn g_original_present = nullptr;
ResizeBuffersFn g_original_resizebuffers = nullptr;
HWND g_hwnd = nullptr;
WNDPROC g_original_wndproc = nullptr;
ID3D11Device* g_device = nullptr;
ID3D11DeviceContext* g_context = nullptr;
ID3D11RenderTargetView* g_rtv = nullptr;
UINT g_bb_width = 0;
UINT g_bb_height = 0;
uintptr_t g_bb_ptr_tag = 0;
void* g_present_fn = nullptr;
void* g_resize_fn = nullptr;
bool g_imgui_initialized = false;
bool g_imgui_context_created = false;
bool g_menu_open = true;
bool g_unhooked = false;

struct Vec3 { float x, y, z; };

// 将世界坐标投影到屏幕
static bool WorldToScreen(const Vec3& p, const Matrix4x4& view, const Matrix4x4& proj,
  float screen_w, float screen_h, ImVec2& out) {
  // Unity Matrix4x4 顺序为行主序 m00 m01 m02 m03 ...，但为避免转置歧义，这里显式写出乘法。
  auto mul_col_major = [](const Matrix4x4& m, const float v[4], float outv[4]) {
    // 视为列主序：先列后行 (匹配常见 Unity → HLSL 乘法)
    outv[0] = m.m[0] * v[0] + m.m[4] * v[1] + m.m[8] * v[2] + m.m[12] * v[3];
    outv[1] = m.m[1] * v[0] + m.m[5] * v[1] + m.m[9] * v[2] + m.m[13] * v[3];
    outv[2] = m.m[2] * v[0] + m.m[6] * v[1] + m.m[10] * v[2] + m.m[14] * v[3];
    outv[3] = m.m[3] * v[0] + m.m[7] * v[1] + m.m[11] * v[2] + m.m[15] * v[3];
  };

  float v[4] = { p.x, p.y, p.z, 1.0f };
  float view_v[4];
  mul_col_major(view, v, view_v);
  float clip[4];
  mul_col_major(proj, view_v, clip);

  if (clip[3] <= 0.001f || clip[2] < 0.0f) return false;  // 背面/在相机后方
  float ndc_x = clip[0] / clip[3];
  float ndc_y = clip[1] / clip[3];
  if (ndc_x < -1.f || ndc_x > 1.f || ndc_y < -1.f || ndc_y > 1.f) return false;

  out.x = (ndc_x * 0.5f + 0.5f) * screen_w;
  out.y = (1.0f - (ndc_y * 0.5f + 0.5f)) * screen_h;
  return true;
}

void LogMessage(const std::string& msg) {
  std::string path = MonoGetLogPath();
  std::ofstream f(path, std::ios::app);
  if (!f) return;
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
  std::tm tm_local{};
  localtime_s(&tm_local, &t);
  f << "[" << std::put_time(&tm_local, "%F %T") << "." << std::setw(3) << std::setfill('0')
    << ms.count() << "] " << msg << "\n";
}

void SetupFonts(ImGuiIO& io) {
  io.Fonts->Clear();
  const char* font_path = "C:\\Windows\\Fonts\\msyh.ttc";  // 微软雅黑，覆盖中文显示
  ImFontConfig cfg;
  cfg.PixelSnapH = true;
  if (!io.Fonts->AddFontFromFileTTF(font_path, 20.0f, &cfg, io.Fonts->GetGlyphRangesChineseFull())) {
    io.Fonts->AddFontDefault();  // 回退到默认字体
  }
  io.Fonts->Build();
}

void CreateRenderTarget(IDXGISwapChain* swap_chain) {
  if (!g_device) return;
  ID3D11Texture2D* back_buffer = nullptr;
  if (SUCCEEDED(swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer))) && back_buffer) {
    g_device->CreateRenderTargetView(back_buffer, nullptr, &g_rtv);
    D3D11_TEXTURE2D_DESC bb_desc{};
    back_buffer->GetDesc(&bb_desc);
    g_bb_width = bb_desc.Width;
    g_bb_height = bb_desc.Height;
    g_bb_ptr_tag = reinterpret_cast<uintptr_t>(back_buffer);
    back_buffer->Release();
    LogMessage("CreateRenderTarget: new RTV created");
  } else {
    LogMessage("CreateRenderTarget: failed to obtain back buffer");
  }
}

void CleanupRenderTarget() {
  if (g_rtv) {
    g_rtv->Release();
    g_rtv = nullptr;
  }
  g_bb_width = g_bb_height = 0;
  g_bb_ptr_tag = 0;
}

HRESULT __stdcall HookResizeBuffers(IDXGISwapChain* swap_chain, UINT buffer_count, UINT width,
                                    UINT height, DXGI_FORMAT format, UINT flags) {
  // Release RTV bound to the old backbuffer before the swap chain recreates buffers.
  CleanupRenderTarget();
  HRESULT hr = g_original_resizebuffers
                 ? g_original_resizebuffers(swap_chain, buffer_count, width, height, format, flags)
                 : DXGI_ERROR_INVALID_CALL;
  if (SUCCEEDED(hr)) {
    CreateRenderTarget(swap_chain);
  }
  return hr;
}

  // 轻量 ESP 绘制：使用相机矩阵把物品/敌人投影到屏幕
  void DrawEsp() {
    if (g_overlay_disabled || MonoIsShuttingDown()) return;
    try {
      ImDrawList* dl = ImGui::GetForegroundDrawList();
      if (!dl) return;
      const ImGuiIO& io = ImGui::GetIO();
      const float sw = io.DisplaySize.x;
      const float sh = io.DisplaySize.y;

      // 缓存矩阵，减少获取频率
      static Matrix4x4 cached_view{};
      static Matrix4x4 cached_proj{};
      static uint64_t last_matrix_time = 0;
      static bool have_cached_mat = false;
      const uint64_t MATRIX_UPDATE_INTERVAL = 33; // 约 30fps 更新一次矩阵
      
      Matrix4x4 view{}, proj{};
      bool have_mat = false;
      uint64_t now = GetTickCount64();
      
      if (now - last_matrix_time > MATRIX_UPDATE_INTERVAL) {
        have_mat = MonoGetCameraMatrices(view, proj);
        if (!have_mat) {
          have_mat = UiGetCachedMatrices(view, proj);
        }
        if (have_mat) {
          cached_view = view;
          cached_proj = proj;
          have_cached_mat = true;
          last_matrix_time = now;
        }
      } else if (have_cached_mat) {
        view = cached_view;
        proj = cached_proj;
        have_mat = true;
      }
      
      if (!have_mat) return;

      // 预计算常用值，避免重复计算
      const ImVec2 screen_center(sw * 0.5f, sh * 0.5f);
      const float max_distance = 1000.0f; // 最大绘制距离

      // 优化的绘制函数
      auto draw_corner_box = [&](const ImVec2& p, float w, float h, ImU32 col, float t = 1.5f) {
        const float lw = w * 0.35f;
        const float lh = h * 0.35f;
        ImVec2 tl(p.x - w * 0.5f, p.y - h * 0.5f);
        ImVec2 br(p.x + w * 0.5f, p.y + h * 0.5f);
        
        // 减少线段数量，只绘制四个角
        dl->AddLine(tl, ImVec2(tl.x + lw, tl.y), col, t);
        dl->AddLine(tl, ImVec2(tl.x, tl.y + lh), col, t);
        dl->AddLine(br, ImVec2(br.x - lw, br.y), col, t);
        dl->AddLine(br, ImVec2(br.x, br.y - lh), col, t);
      };

      auto draw_label = [&](const ImVec2& pos, ImU32 col, const char* text) {
        if (text && *text) {
          dl->AddText(ImVec2(pos.x + 6, pos.y - 14), col, text);
        }
      };

      // 缓存颜色值，避免重复计算
      static ImU32 cached_colors[11] = {};
      static bool colors_cached = false;
      if (!colors_cached) {
        for (int i = 0; i <= 10; ++i) {
          float z = i * 0.1f;
          float fade = 1.0f - std::min(std::max(z, 0.0f), 1.0f);
          int alpha = static_cast<int>(180.0f * fade + 40.0f);
          if (alpha < 40) alpha = 40;
          cached_colors[i] = IM_COL32(230, 201, 60, alpha);
        }
        colors_cached = true;
      }

      auto depth_col = [&](float z) -> ImU32 {
        int index = static_cast<int>(std::min(std::max(z * 10.0f, 0.0f), 10.0f));
        return cached_colors[index];
      };

      auto compute_box = [&](float ndc_z, float base_h, float base_w) {
        float depth_scale = 1.0f - std::min(std::max(ndc_z, 0.0f), 0.9f);
        if (depth_scale < 0.25f) depth_scale = 0.25f;
        float h = base_h * depth_scale;
        float w = base_w * depth_scale;
        return std::pair<float, float>(w, h);
      };

      // 绘制物品 ESP
      const auto& items = UiGetCachedItems();
      if (g_item_esp_enabled && !items.empty()) {
        size_t cap = items.size();
        if (g_item_esp_cap >= 0 && static_cast<size_t>(g_item_esp_cap) < cap) cap = static_cast<size_t>(g_item_esp_cap);
        const size_t max_cap = 512; // 减少最大绘制数量
        if (cap > max_cap) cap = max_cap;
        
        // 开始批量绘制
        dl->PushClipRectFullScreen();
        
        // 预分配绘制命令空间，减少动态分配
        dl->ChannelsSplit(1);
        
        for (size_t i = 0; i < cap; ++i) {
          const auto& st = items[i];
          if (!st.has_position) continue;
          
          // 只绘制有价值的物品
          if (!st.has_value || st.value <= 0) continue;
          
          ImVec2 sp;
          // 将 ndc_z 作为深度衰减依据；WorldToScreen 已有 clipZ check
          if (!WorldToScreen({ st.x, st.y, st.z }, view, proj, sw, sh, sp)) continue;
          
          // 计算深度和颜色
          float ndc_z = 0.5f;  // 默认中等距离
          ImU32 col;
          
          // 根据物品类型设置不同的颜色
          int alpha = static_cast<int>(180.0f * (1.0f - ndc_z) + 40.0f);
          if (alpha < 40) alpha = 40;
          
          // 首先检查物品名称是否包含"player"，如果是，则显示为玩家并使用紫色绘制
          if (st.has_name) {
            std::string lower_name = st.name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
            if (lower_name.find("player") != std::string::npos) {
              col = IM_COL32(148, 0, 211, alpha);  // 紫色 - 玩家
            }
            // 然后检查物品名称是否包含"贵重物品"
            else if (st.name.find("贵重物品") != std::string::npos) {
              col = IM_COL32(230, 201, 60, alpha);  // 黄色 - 贵重物品
            }
            // 最后根据物品类别设置颜色
            else {
              switch (st.category) {
                case PlayerState::Category::kValuable:
                  col = IM_COL32(230, 201, 60, alpha);  // 黄色 - 贵重物品
                  break;
                case PlayerState::Category::kPhysGrab:
                  col = IM_COL32(48, 131, 83, alpha);  // 绿色 - 可抓取
                  break;
                case PlayerState::Category::kVolume:
                  col = IM_COL32(100, 149, 237, alpha);  // 蓝色 - 物品容器
                  break;
                default:
                  col = IM_COL32(169, 169, 169, alpha);  // 灰色 - 其他
                  break;
              }
            }
          }
          // 如果没有名称，则根据物品类别设置颜色
          else {
            switch (st.category) {
              case PlayerState::Category::kValuable:
                col = IM_COL32(230, 201, 60, alpha);  // 黄色 - 贵重物品
                break;
              case PlayerState::Category::kPhysGrab:
                col = IM_COL32(48, 131, 83, alpha);  // 绿色 - 可抓取
                break;
              case PlayerState::Category::kVolume:
                col = IM_COL32(100, 149, 237, alpha);  // 蓝色 - 物品容器
                break;
              default:
                col = IM_COL32(169, 169, 169, alpha);  // 灰色 - 其他
                break;
            }
          }
          
          // 计算框大小并绘制
          auto sz = compute_box(ndc_z, 28.0f, 18.0f); // 减小默认大小
          draw_corner_box(sp, sz.first, sz.second, col, 1.5f); // 减小线宽
          
          // 绘制标签
          if (st.has_name) {
            draw_label(sp, col, st.name.c_str());
          }
        }
        
        // 结束批量绘制
        dl->PopClipRect();
      }

      // 绘制敌人 ESP
      const auto& enemies = UiGetCachedEnemies();
      if (g_enemy_esp_enabled && !g_enemy_esp_disabled && !enemies.empty()) {
        size_t cap = enemies.size();
        if (g_enemy_esp_cap >= 0 && static_cast<size_t>(g_enemy_esp_cap) < cap) cap = static_cast<size_t>(g_enemy_esp_cap);
        const size_t max_cap = 512;
        if (cap > max_cap) cap = max_cap;
        
        // 开始批量绘制
        dl->PushClipRectFullScreen();
        
        for (size_t i = 0; i < cap; ++i) {
          const auto& st = enemies[i];
          if (!st.has_position) continue;
          
          // 检查怪物是否太久不动，如果是，则跳过绘制
          if (st.IsTooLongIdle()) continue;
          
          ImVec2 sp;
          if (!WorldToScreen({ st.x, st.y, st.z }, view, proj, sw, sh, sp)) continue;
          
          // 计算深度和颜色
          float ndc_z = 0.5f;
          ImU32 col = IM_COL32(220, 64, 64, static_cast<int>(220 - ndc_z * 120));
          
          // 计算框大小并绘制
          auto sz = compute_box(ndc_z, 36.0f, 20.0f);
          draw_corner_box(sp, sz.first, sz.second, col, 2.2f);
          
          // 绘制标签
          draw_label(sp, col, st.has_name ? st.name.c_str() : "敌人");
        }
        
        // 结束批量绘制
        dl->PopClipRect();
      }
    }
    catch (...) {
      LogCrash("DrawEsp", 0, nullptr);
    }
  }

LRESULT CALLBACK WndProcHook(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  static bool last_menu_open = false;
  
  if (msg == WM_KEYUP && wparam == VK_INSERT) {
    g_menu_open = !g_menu_open;
    // 菜单状态变化时控制鼠标指针
    if (g_menu_open) {
      while (ShowCursor(TRUE) < 0);  // 显示鼠标指针
    } else {
      while (ShowCursor(FALSE) >= 0);  // 隐藏鼠标指针
    }
    last_menu_open = g_menu_open;
    return 0;
  }
  
  // 检查菜单状态是否变化
  if (g_menu_open != last_menu_open) {
    if (g_menu_open) {
      while (ShowCursor(TRUE) < 0);  // 显示鼠标指针
    } else {
      while (ShowCursor(FALSE) >= 0);  // 隐藏鼠标指针
    }
    last_menu_open = g_menu_open;
  }
  
  if (MonoIsShuttingDown()) {
    return CallWindowProc(g_original_wndproc, hwnd, msg, wparam, lparam);
  }

  if (g_menu_open) {
    ImGuiIO& io = ImGui::GetIO();
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam)) {
      return 1;
    }
    // Only swallow inputs when ImGui wants them, so game clicks still pass through.
    const bool want_mouse = io.WantCaptureMouse;
    const bool want_keyboard = io.WantCaptureKeyboard || io.WantTextInput;
    if (want_mouse) {
      switch (msg) {
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
        case WM_MBUTTONDOWN:
        case WM_MBUTTONUP:
        case WM_MOUSEMOVE:
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
          return 1;
        default:
          break;
      }
    }
    if (want_keyboard) {
      switch (msg) {
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP:
          return 1;
        default:
          break;
      }
    }
  }

  return CallWindowProc(g_original_wndproc, hwnd, msg, wparam, lparam);
}

// Helper with C++ logic; called from HookPresent inside SEH wrapper.
static bool DeviceWasRemoved() {
  if (!g_device) {
    return false;
  }
  HRESULT removed = g_device->GetDeviceRemovedReason();
  return FAILED(removed);
}

// Detect backbuffer changes (size or pointer) and rebuild RTV when needed.
static void EnsureRenderTargetFresh(IDXGISwapChain* swap_chain) {
  bool need_rebuild = (g_rtv == nullptr);

  DXGI_SWAP_CHAIN_DESC desc{};
  if (SUCCEEDED(swap_chain->GetDesc(&desc))) {
    if (desc.BufferDesc.Width != g_bb_width || desc.BufferDesc.Height != g_bb_height) {
      need_rebuild = true;
      std::ostringstream oss;
      oss << "PresentFrame: backbuffer size changed " << g_bb_width << "x" << g_bb_height
          << " -> " << desc.BufferDesc.Width << "x" << desc.BufferDesc.Height;
      LogMessage(oss.str());
    }
  }

  ID3D11Texture2D* bb = nullptr;
  if (SUCCEEDED(swap_chain->GetBuffer(0, IID_PPV_ARGS(&bb))) && bb) {
    uintptr_t tag = reinterpret_cast<uintptr_t>(bb);
    if (tag != g_bb_ptr_tag) {
      need_rebuild = true;
      std::ostringstream oss;
      oss << "PresentFrame: backbuffer pointer changed tag=0x" << std::hex << g_bb_ptr_tag
          << " -> 0x" << tag;
      LogMessage(oss.str());
    }
    bb->Release();
  }

  if (need_rebuild) {
    CleanupRenderTarget();
    CreateRenderTarget(swap_chain);
  }
}

static void ResetImguiDeviceState() {
  ImGui_ImplDX11_Shutdown();
  CleanupRenderTarget();
  if (g_context) {
    g_context->Release();
    g_context = nullptr;
  }
  if (g_device) {
    g_device->Release();
    g_device = nullptr;
  }
  g_rtv = nullptr;
  g_imgui_initialized = false;
}

static HRESULT PresentFrame(IDXGISwapChain* swap_chain, UINT sync_interval, UINT flags) {
  SetCrashStage("PresentFrame:enter");
  if (!g_original_present) {
    LogMessage("HookPresent: original_present null, skipping");
    return DXGI_ERROR_INVALID_CALL;
  }
  static bool logged_present_once = false;
  if (!logged_present_once) {
    LogMessage("HookPresent: entered");
    logged_present_once = true;
  }
  if (MonoIsShuttingDown()) {
    return g_original_present(swap_chain, sync_interval, flags);
  }
  if (!g_imgui_initialized) {
    if (SUCCEEDED(swap_chain->GetDevice(__uuidof(ID3D11Device),
      reinterpret_cast<void**>(&g_device))) &&
      g_device) {
      g_device->GetImmediateContext(&g_context);
      DXGI_SWAP_CHAIN_DESC desc = {};
      swap_chain->GetDesc(&desc);
      g_hwnd = desc.OutputWindow;
      g_original_wndproc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtr(g_hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(WndProcHook)));

      CreateRenderTarget(swap_chain);

      if (!g_imgui_context_created) {
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        SetupFonts(io);
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;
        io.MouseDrawCursor = false;  // 禁用 ImGui 鼠标指针绘制，使用系统鼠标指针
        ImGui::StyleColorsDark();
        ImGui_ImplWin32_Init(g_hwnd);
        g_imgui_context_created = true;
      }
      ImGui_ImplDX11_Init(g_device, g_context);

      g_imgui_initialized = true;
    }
  }

  if (g_imgui_initialized) {
    SetCrashStage("PresentFrame:check_device");
    if (DeviceWasRemoved()) {
      LogMessage("HookPresent: device removed detected, resetting overlay");
      ResetImguiDeviceState();
      // 不要直接返回，让代码继续执行，下一次调用时会重新初始化 ImGui
    }
    else if (g_overlay_disabled) {
      return g_original_present(swap_chain, sync_interval, flags);
    }
    else {
      EnsureRenderTargetFresh(swap_chain);
      if (!g_rtv) {
        LogMessage("HookPresent: g_rtv null after refresh, rendering skipped");
        return g_original_present(swap_chain, sync_interval, flags);
      }

      ImGui_ImplDX11_NewFrame();
      ImGui_ImplWin32_NewFrame();
      ImGui::NewFrame();

      SetCrashStage("RenderOverlay");
      // Render without SEH to avoid mixed exception models (C2712). Upstream catch is in HookPresent.
      RenderOverlay(&g_menu_open);
      SetCrashStage("RenderOverlay:DrawEsp");
      DrawEsp();
      ImGui::Render();

      if (!g_rtv) {
        CreateRenderTarget(swap_chain);
      }
      if (g_rtv) {
        g_context->OMSetRenderTargets(1, &g_rtv, nullptr);
      }
      ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }
  }

  return g_original_present(swap_chain, sync_interval, flags);
}

HRESULT __stdcall HookPresent(IDXGISwapChain* swap_chain, UINT sync_interval, UINT flags) {
#ifdef _MSC_VER
  __try {
    return PresentFrame(swap_chain, sync_interval, flags);
  }
  __except (LogCrash("HookPresent", GetExceptionCode(), GetExceptionInformation())) {
    g_overlay_disabled = true;
    ResetImguiDeviceState();
    return g_original_present ? g_original_present(swap_chain, sync_interval, flags) : DXGI_ERROR_INVALID_CALL;
  }
#else
  return PresentFrame(swap_chain, sync_interval, flags);
#endif
}

bool CreateDx11Hook() {
  LogMessage("CreateDx11Hook: begin");
  WNDCLASSEXW wc = {};
  wc.cbSize = sizeof(wc);
  wc.style = CS_CLASSDC;
  wc.lpfnWndProc = DefWindowProcW;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.lpszClassName = L"RepoDLL_DX11";

  if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
    LogMessage("CreateDx11Hook: RegisterClassExW failed");
    return false;
  }

  HWND hwnd = CreateWindowW(wc.lpszClassName, L"RepoDLL_DX11", WS_OVERLAPPEDWINDOW,
                            0, 0, 100, 100, nullptr, nullptr, wc.hInstance, nullptr);
  if (!hwnd) {
    LogMessage("CreateDx11Hook: CreateWindowW failed");
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return false;
  }

  DXGI_SWAP_CHAIN_DESC sd = {};
  sd.BufferCount = 1;
  sd.BufferDesc.Width = 2;
  sd.BufferDesc.Height = 2;
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = hwnd;
  sd.SampleDesc.Count = 1;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

  ID3D11Device* device = nullptr;
  ID3D11DeviceContext* context = nullptr;
  IDXGISwapChain* swap_chain = nullptr;
  D3D_FEATURE_LEVEL feature_level;

  HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                             nullptr, 0, D3D11_SDK_VERSION, &sd, &swap_chain,
                                             &device, &feature_level, &context);
  if (FAILED(hr)) {
    std::ostringstream oss;
    oss << "CreateDx11Hook: D3D11CreateDeviceAndSwapChain failed hr=0x" << std::hex << hr;
    LogMessage(oss.str());
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return false;
  }

  void** vtable = *reinterpret_cast<void***>(swap_chain);
  void* present = vtable[8];
  void* resizebuffers = vtable[13];
  if (!present) {
    LogMessage("CreateDx11Hook: present vtable null");
  }
  if (!resizebuffers) {
    LogMessage("CreateDx11Hook: resizebuffers vtable null");
  }
  g_present_fn = present;
  g_resize_fn = resizebuffers;

  swap_chain->Release();
  context->Release();
  device->Release();
  DestroyWindow(hwnd);
  UnregisterClassW(wc.lpszClassName, wc.hInstance);

  if (MH_Initialize() != MH_OK) {
    LogMessage("CreateDx11Hook: MH_Initialize failed");
    return false;
  }

  if (MH_CreateHook(present, HookPresent, reinterpret_cast<void**>(&g_original_present)) !=
      MH_OK) {
    LogMessage("CreateDx11Hook: MH_CreateHook failed");
    MH_Uninitialize();
    return false;
  }
  if (resizebuffers &&
      MH_CreateHook(resizebuffers, HookResizeBuffers,
                    reinterpret_cast<void**>(&g_original_resizebuffers)) != MH_OK) {
    LogMessage("CreateDx11Hook: MH_CreateHook ResizeBuffers failed");
    MH_RemoveHook(present);
    MH_Uninitialize();
    return false;
  }

  if (MH_EnableHook(present) != MH_OK) {
    LogMessage("CreateDx11Hook: MH_EnableHook failed");
    MH_RemoveHook(present);
    if (resizebuffers) MH_RemoveHook(resizebuffers);
    MH_Uninitialize();
    return false;
  }
  if (resizebuffers && MH_EnableHook(resizebuffers) != MH_OK) {
    LogMessage("CreateDx11Hook: MH_EnableHook ResizeBuffers failed");
    MH_RemoveHook(present);
    MH_RemoveHook(resizebuffers);
    MH_Uninitialize();
    return false;
  }

  LogMessage("CreateDx11Hook: success");
  return true;
}
}  // namespace

bool HookDx11() {
  LogMessage("HookDx11: initializing");
  if (!CreateDx11Hook()) {
    LogMessage("HookDx11: CreateDx11Hook failed");
    return false;
  }
  LogMessage("HookDx11: hook installed");
  return true;
}

void UnhookDx11() {
  if (g_unhooked) return;
  g_unhooked = true;

  LogMessage("UnhookDx11: begin");

  if (g_imgui_context_created) {
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    g_imgui_context_created = false;
  }
  g_imgui_initialized = false;

  if (g_rtv) {
    g_rtv->Release();
    g_rtv = nullptr;
  }
  if (g_context) {
    g_context->Release();
    g_context = nullptr;
  }
  if (g_device) {
    g_device->Release();
    g_device = nullptr;
  }

  if (g_hwnd && g_original_wndproc) {
    SetWindowLongPtr(g_hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(g_original_wndproc));
    g_original_wndproc = nullptr;
    g_hwnd = nullptr;
  }

  if (g_present_fn && g_original_present) {
    MH_DisableHook(g_present_fn);
    MH_RemoveHook(g_present_fn);
    g_present_fn = nullptr;
  }
  if (g_resize_fn && g_original_resizebuffers) {
    MH_DisableHook(g_resize_fn);
    MH_RemoveHook(g_resize_fn);
    g_resize_fn = nullptr;
  }
  MH_Uninitialize();

  g_original_present = nullptr;
  LogMessage("UnhookDx11: done");
}
