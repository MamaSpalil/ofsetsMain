/*
 * MainWindow.h - Win32 GUI Main Window for MuTracker Loader
 *
 * Provides a professional-looking native Win32 window with:
 *   - Process finder and status indicator
 *   - DLL injection controls
 *   - Real-time trace data ListView
 *   - Statistics display
 *   - Log output area
 *   - Export / Clear / Pause controls
 *
 * Compile: MSVC 2019+ (v142), C++17, Win32/x64
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <functional>

#include "resource.h"
#include "TraceViewer.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")

namespace MuTracker {

/* ================================================================== */
/*  Window Constants                                                   */
/* ================================================================== */

static const int WINDOW_WIDTH      = 820;
static const int WINDOW_HEIGHT     = 680;
static const int MARGIN            = 12;
static const int CONTROL_HEIGHT    = 24;
static const int BUTTON_HEIGHT     = 30;
static const int BUTTON_WIDTH      = 140;
static const int LISTVIEW_HEIGHT   = 280;
static const int LOG_HEIGHT        = 100;
static const int LABEL_WIDTH       = 70;

/* ================================================================== */
/*  Color Scheme (Dark theme inspired)                                 */
/* ================================================================== */

static const COLORREF CLR_BG_MAIN      = RGB(30,  30,  35);
static const COLORREF CLR_BG_CONTROLS  = RGB(40,  40,  48);
static const COLORREF CLR_BG_EDIT      = RGB(45,  45,  55);
static const COLORREF CLR_BG_LISTVIEW  = RGB(35,  35,  42);
static const COLORREF CLR_BG_LOG       = RGB(25,  25,  30);
static const COLORREF CLR_BG_BUTTON    = RGB(55,  55,  70);
static const COLORREF CLR_BG_BTN_HOVER = RGB(70,  70,  90);
static const COLORREF CLR_TEXT         = RGB(220, 220, 230);
static const COLORREF CLR_TEXT_DIM     = RGB(140, 140, 160);
static const COLORREF CLR_ACCENT       = RGB(80, 160, 255);
static const COLORREF CLR_GREEN        = RGB(80, 200, 120);
static const COLORREF CLR_RED          = RGB(220, 80,  80);
static const COLORREF CLR_YELLOW       = RGB(220, 200, 80);
static const COLORREF CLR_SEPARATOR    = RGB(60,  60,  75);
static const COLORREF CLR_HEADER_BG    = RGB(50,  50,  62);

/* ================================================================== */
/*  MainWindow Class                                                   */
/* ================================================================== */

class MainWindow {
public:
    MainWindow();
    ~MainWindow();

    /* Create and show the window */
    bool Create(HINSTANCE hInstance, int nCmdShow);

    /* Run the message loop (returns exit code) */
    int Run();

    /* Access the window handle */
    HWND GetHWND() const { return m_hWnd; }

    /* Log a message to the log area */
    void AppendLog(const char* format, ...);

    /* Set injection callbacks */
    using InjectCallback = std::function<bool(DWORD pid, const std::wstring& dllPath)>;
    using EjectCallback  = std::function<bool(DWORD pid)>;
    using FindCallback   = std::function<DWORD(const char* procName)>;

    void SetInjectCallback(InjectCallback cb)   { m_onInject = cb; }
    void SetEjectCallback(EjectCallback cb)     { m_onEject = cb; }
    void SetFindCallback(FindCallback cb)       { m_onFind = cb; }

private:
    /* Window procedure */
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg,
                                     WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

    /* Initialization helpers */
    bool RegisterWindowClass(HINSTANCE hInstance);
    void CreateControls();
    void InitListView();
    void ApplyDarkTheme();

    /* Layout */
    void OnResize(int width, int height);

    /* Command handlers */
    void OnFindProcess();
    void OnInjectDLL();
    void OnEjectDLL();
    void OnBrowseDLL();
    void OnExportCSV();
    void OnClearLog();
    void OnPauseResume();
    void OnSettings();

    /* Timer update */
    void OnUpdateTimer();
    void UpdateListView();
    void UpdateStatusBar();

    /* Custom drawing */
    void PaintBackground(HDC hdc, const RECT& rc);
    void DrawSeparator(HDC hdc, int y, int width);
    LRESULT OnCtlColorStatic(HDC hdc, HWND hCtl);
    LRESULT OnCtlColorEdit(HDC hdc, HWND hCtl);
    LRESULT OnCustomDrawListView(LPNMLVCUSTOMDRAW lpcd);

    /* ============================================================== */
    /*  Data                                                           */
    /* ============================================================== */

    HINSTANCE   m_hInstance;
    HWND        m_hWnd;
    HFONT       m_hFont;
    HFONT       m_hFontBold;
    HFONT       m_hFontMono;
    HBRUSH      m_hBrushBg;
    HBRUSH      m_hBrushCtrl;
    HBRUSH      m_hBrushEdit;
    HBRUSH      m_hBrushLog;

    /* Controls */
    HWND    m_hEditProcess;
    HWND    m_hBtnFind;
    HWND    m_hStaticStatus;
    HWND    m_hStaticPid;
    HWND    m_hEditDllPath;
    HWND    m_hBtnBrowse;
    HWND    m_hBtnInject;
    HWND    m_hBtnEject;
    HWND    m_hBtnSettings;
    HWND    m_hStaticHooks;
    HWND    m_hStaticCalls;
    HWND    m_hStaticDropped;
    HWND    m_hListView;
    HWND    m_hEditLog;
    HWND    m_hBtnExport;
    HWND    m_hBtnClear;
    HWND    m_hBtnPause;
    HWND    m_hStatusBar;

    /* State */
    DWORD   m_targetPid;
    bool    m_attached;
    bool    m_paused;
    std::wstring m_dllPath;

    /* Trace viewer */
    TraceViewer m_traceViewer;

    /* Callbacks */
    InjectCallback  m_onInject;
    EjectCallback   m_onEject;
    FindCallback    m_onFind;
};

} /* namespace MuTracker */
