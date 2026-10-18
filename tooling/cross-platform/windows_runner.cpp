// SPDX-License-Identifier: GPL-3.0-only
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include "flutter_windows.h"
static FlutterDesktopViewControllerRef controller = nullptr;
static HWND child = nullptr;
LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  if (controller) { LRESULT result; if (FlutterDesktopViewControllerHandleTopLevelWindowProc(controller,window,message,wparam,lparam,&result)) return result; }
  switch(message) {
    case WM_SIZE: if(child) MoveWindow(child,0,0,LOWORD(lparam),HIWORD(lparam),TRUE); return 0;
    case WM_SETFOCUS: if(child) SetFocus(child); return 0;
    case WM_GETMINMAXINFO: { auto m=reinterpret_cast<MINMAXINFO*>(lparam);m->ptMinTrackSize={420,640}; return 0; }
    case WM_DESTROY: if(controller) { auto old=controller;controller=nullptr;child=nullptr;FlutterDesktopViewControllerDestroy(old); } PostQuitMessage(0); return 0;
  }
  return DefWindowProcW(window,message,wparam,lparam);
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
  WNDCLASSW wc{};wc.lpfnWndProc=WindowProc;wc.hInstance=instance;wc.lpszClassName=L"XIOClient019";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hIcon=LoadIconW(instance,MAKEINTRESOURCEW(101));RegisterClassW(&wc);
  HWND window=CreateWindowW(wc.lpszClassName,L"XIO",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,540,850,nullptr,nullptr,instance,nullptr);
  FlutterDesktopEngineProperties properties{};
  properties.assets_path=L"data\\flutter_assets";properties.icu_data_path=L"data\\icudtl.dat";properties.aot_library_path=L"data\\app.so";
  properties.gpu_preference=LowPowerPreference;
  properties.ui_thread_policy=RunOnPlatformThread;
  properties.impeller_switch=DefaultImpeller;
  auto engine=FlutterDesktopEngineCreate(&properties);
  if(!engine) { MessageBoxW(window,L"Could not start the Flutter engine. Extract the complete XIO archive.",L"XIO",MB_ICONERROR); return 1; }
  RECT area{};GetClientRect(window,&area);
  controller=FlutterDesktopViewControllerCreate(area.right,area.bottom,engine);
  if(!controller) return 2;
  child=FlutterDesktopViewGetHWND(FlutterDesktopViewControllerGetView(controller));SetParent(child,window);MoveWindow(child,0,0,area.right,area.bottom,TRUE);
  FlutterDesktopEngineSetNextFrameCallback(engine,[](void* data){ShowWindow(static_cast<HWND>(data),SW_SHOWNORMAL);},window);
  ShowWindow(child,SW_SHOW);SetFocus(child);
  FlutterDesktopViewControllerForceRedraw(controller);
  MSG message{};while(GetMessageW(&message,nullptr,0,0)>0) { TranslateMessage(&message);DispatchMessageW(&message); }
  CoUninitialize();return static_cast<int>(message.wParam);
}
