/*
 * MainWindow.cpp - Win32 GUI Main Window implementation
 *
 * Beautiful dark-themed native Win32 window for MuTracker Loader.
 * Uses Common Controls v6 with custom owner-draw for a modern look.
 *
 * Compile: MSVC 2019+ (v142), C++17, Win32/x64
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <uxtheme.h>
#include <dwmapi.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")

#include "MainWindow.h"

#include <cstdio>
#include <cstdarg>

namespace MuTracker {

/* ================================================================== */
/*  Window Class Name                                                  */
/* ================================================================== */

static const wchar_t* WND_CLASS_NAME = L"MuTrackerMainWindow";
static const wchar_t* WND_TITLE      = L"MuOnline Tracker v1.0";

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

MainWindow::MainWindow()
    : m_hInstance(nullptr)
    , m_hWnd(nullptr)
    , m_hFont(nullptr)
    , m_hFontBold(nullptr)
    , m_hFontMono(nullptr)
    , m_hBrushBg(nullptr)
    , m_hBrushCtrl(nullptr)
    , m_hBrushEdit(nullptr)
    , m_hBrushLog(nullptr)
    , m_hEditProcess(nullptr)
    , m_hBtnFind(nullptr)
    , m_hStaticStatus(nullptr)
    , m_hStaticPid(nullptr)
    , m_hEditDllPath(nullptr)
    , m_hBtnBrowse(nullptr)
    , m_hBtnInject(nullptr)
    , m_hBtnEject(nullptr)
    , m_hBtnSettings(nullptr)
    , m_hStaticHooks(nullptr)
    , m_hStaticCalls(nullptr)
    , m_hStaticDropped(nullptr)
    , m_hListView(nullptr)
    , m_hEditLog(nullptr)
    , m_hBtnExport(nullptr)
    , m_hBtnClear(nullptr)
    , m_hBtnPause(nullptr)
    , m_hStatusBar(nullptr)
    , m_targetPid(0)
    , m_attached(false)
    , m_paused(false)
{
}

MainWindow::~MainWindow()
{
    if (m_hFont)      DeleteObject(m_hFont);
    if (m_hFontBold)  DeleteObject(m_hFontBold);
    if (m_hFontMono)  DeleteObject(m_hFontMono);
    if (m_hBrushBg)   DeleteObject(m_hBrushBg);
    if (m_hBrushCtrl) DeleteObject(m_hBrushCtrl);
    if (m_hBrushEdit) DeleteObject(m_hBrushEdit);
    if (m_hBrushLog)  DeleteObject(m_hBrushLog);
}

/* ================================================================== */
/*  Create & Show                                                      */
/* ================================================================== */

bool MainWindow::Create(HINSTANCE hInstance, int nCmdShow)
{
    m_hInstance = hInstance;

    /* Initialize common controls (for ListView, StatusBar) */
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    if (!RegisterWindowClass(hInstance)) {
        return false;
    }

    /* Create fonts */
    m_hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    m_hFontBold = CreateFontW(-14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                               CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                               DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    m_hFontMono = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                               CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                               FIXED_PITCH | FF_MODERN, L"Consolas");

    /* Create brushes */
    m_hBrushBg   = CreateSolidBrush(CLR_BG_MAIN);
    m_hBrushCtrl = CreateSolidBrush(CLR_BG_CONTROLS);
    m_hBrushEdit = CreateSolidBrush(CLR_BG_EDIT);
    m_hBrushLog  = CreateSolidBrush(CLR_BG_LOG);

    /* Center on screen */
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenW - WINDOW_WIDTH) / 2;
    int posY = (screenH - WINDOW_HEIGHT) / 2;

    /* Create main window */
    m_hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        WND_CLASS_NAME,
        WND_TITLE,
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX,
        posX, posY, WINDOW_WIDTH, WINDOW_HEIGHT,
        nullptr, nullptr, hInstance, this);

    if (!m_hWnd) {
        return false;
    }

    /* Apply dark title bar (Windows 10 1809+) */
    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(m_hWnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */,
                           &darkMode, sizeof(darkMode));

    /* Create all child controls */
    CreateControls();
    ApplyDarkTheme();

    /* Get DLL path (same directory as loader) */
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    m_dllPath = exePath;
    size_t lastSlash = m_dllPath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        m_dllPath = m_dllPath.substr(0, lastSlash + 1);
    }
    m_dllPath += L"MuTrackerDLL.dll";
    SetWindowTextW(m_hEditDllPath, m_dllPath.c_str());

    /* Set default process name */
    SetWindowTextA(m_hEditProcess, "main.exe");

    /* Start update timer (500ms) */
    SetTimer(m_hWnd, IDT_UPDATE_TIMER, 500, nullptr);

    ShowWindow(m_hWnd, nCmdShow);
    UpdateWindow(m_hWnd);

    AppendLog("[MuTracker] Loader started. Ready to attach to MuOnline.\r\n");

    return true;
}

/* ================================================================== */
/*  Message Loop                                                       */
/* ================================================================== */

int MainWindow::Run()
{
    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

/* ================================================================== */
/*  Register Window Class                                              */
/* ================================================================== */

bool MainWindow::RegisterWindowClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = sizeof(LONG_PTR);
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = m_hBrushBg;
    wc.lpszMenuName  = nullptr;
    wc.lpszClassName = WND_CLASS_NAME;
    wc.hIconSm      = LoadIconW(nullptr, IDI_APPLICATION);

    return RegisterClassExW(&wc) != 0;
}

/* ================================================================== */
/*  Window Procedure                                                   */
/* ================================================================== */

LRESULT CALLBACK MainWindow::WndProc(HWND hWnd, UINT msg,
                                      WPARAM wParam, LPARAM lParam)
{
    MainWindow* pThis = nullptr;

    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        pThis = static_cast<MainWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA,
                           reinterpret_cast<LONG_PTR>(pThis));
        pThis->m_hWnd = hWnd;
    } else {
        pThis = reinterpret_cast<MainWindow*>(
            GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    }

    if (pThis) {
        return pThis->HandleMessage(msg, wParam, lParam);
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_FIND:      OnFindProcess(); return 0;
        case IDC_BTN_INJECT:    OnInjectDLL();   return 0;
        case IDC_BTN_EJECT:     OnEjectDLL();    return 0;
        case IDC_BTN_BROWSE:    OnBrowseDLL();   return 0;
        case IDC_BTN_EXPORT:    OnExportCSV();   return 0;
        case IDC_BTN_CLEAR:     OnClearLog();    return 0;
        case IDC_BTN_PAUSE:     OnPauseResume(); return 0;
        case IDC_BTN_SETTINGS:  OnSettings();    return 0;
        case IDM_FILE_EXIT:     DestroyWindow(m_hWnd); return 0;
        }
        break;

    case WM_TIMER:
        if (wParam == IDT_UPDATE_TIMER && !m_paused) {
            OnUpdateTimer();
        }
        return 0;

    case WM_SIZE:
        OnResize(LOWORD(lParam), HIWORD(lParam));
        return 0;

    case WM_CTLCOLORSTATIC:
        return OnCtlColorStatic(reinterpret_cast<HDC>(wParam),
                                 reinterpret_cast<HWND>(lParam));

    case WM_CTLCOLOREDIT:
        return OnCtlColorEdit(reinterpret_cast<HDC>(wParam),
                               reinterpret_cast<HWND>(lParam));

    case WM_NOTIFY: {
        auto* nmhdr = reinterpret_cast<NMHDR*>(lParam);
        if (nmhdr->idFrom == IDC_LISTVIEW_TRACE &&
            nmhdr->code == NM_CUSTOMDRAW) {
            return OnCustomDrawListView(
                reinterpret_cast<LPNMLVCUSTOMDRAW>(lParam));
        }
        break;
    }

    case WM_ERASEBKGND: {
        HDC hdc = reinterpret_cast<HDC>(wParam);
        RECT rc;
        GetClientRect(m_hWnd, &rc);
        FillRect(hdc, &rc, m_hBrushBg);
        return 1;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(m_hWnd, &ps);
        PaintBackground(hdc, ps.rcPaint);
        EndPaint(m_hWnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        KillTimer(m_hWnd, IDT_UPDATE_TIMER);
        m_traceViewer.Disconnect();
        PostQuitMessage(0);
        return 0;

    case WM_GETMINMAXINFO: {
        auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        mmi->ptMinTrackSize.x = 700;
        mmi->ptMinTrackSize.y = 550;
        return 0;
    }
    }

    return DefWindowProcW(m_hWnd, msg, wParam, lParam);
}

/* ================================================================== */
/*  Create Controls                                                    */
/* ================================================================== */

void MainWindow::CreateControls()
{
    int x = MARGIN;
    int y = MARGIN;
    int cw = WINDOW_WIDTH - MARGIN * 2 - 16; /* client width */

    /* ── Title label ────────────────────────────────────── */
    HWND hTitle = CreateWindowExW(0, L"STATIC",
        L"\x2588 MuOnline Tracker v1.0",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        x, y, cw, 22,
        m_hWnd, nullptr, m_hInstance, nullptr);
    SendMessageW(hTitle, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);
    y += 28;

    /* ── Process row ────────────────────────────────────── */
    HWND hLblProc = CreateWindowExW(0, L"STATIC", L"Process:",
        WS_CHILD | WS_VISIBLE | SS_RIGHT,
        x, y + 3, LABEL_WIDTH, CONTROL_HEIGHT,
        m_hWnd, nullptr, m_hInstance, nullptr);
    SendMessageW(hLblProc, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    m_hEditProcess = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        x + LABEL_WIDTH + 6, y, 160, CONTROL_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_EDIT_PROCESS, m_hInstance, nullptr);
    SendMessageW(m_hEditProcess, WM_SETFONT, (WPARAM)m_hFontMono, TRUE);

    m_hBtnFind = CreateWindowExW(0, L"BUTTON", L"\xD83D\xDD0D Find",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x + LABEL_WIDTH + 172, y, 80, CONTROL_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_BTN_FIND, m_hInstance, nullptr);
    SendMessageW(m_hBtnFind, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    m_hStaticStatus = CreateWindowExW(0, L"STATIC",
        L"\x25CF Not attached",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        x + LABEL_WIDTH + 260, y + 3, 200, CONTROL_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_STATIC_STATUS, m_hInstance, nullptr);
    SendMessageW(m_hStaticStatus, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    m_hStaticPid = CreateWindowExW(0, L"STATIC", L"PID: ---",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        x + LABEL_WIDTH + 470, y + 3, 120, CONTROL_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_STATIC_PID, m_hInstance, nullptr);
    SendMessageW(m_hStaticPid, WM_SETFONT, (WPARAM)m_hFontMono, TRUE);

    y += CONTROL_HEIGHT + 8;

    /* ── DLL path row ───────────────────────────────────── */
    HWND hLblDll = CreateWindowExW(0, L"STATIC", L"DLL:",
        WS_CHILD | WS_VISIBLE | SS_RIGHT,
        x, y + 3, LABEL_WIDTH, CONTROL_HEIGHT,
        m_hWnd, nullptr, m_hInstance, nullptr);
    SendMessageW(hLblDll, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    m_hEditDllPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
        x + LABEL_WIDTH + 6, y, cw - LABEL_WIDTH - 46, CONTROL_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_EDIT_DLLPATH, m_hInstance, nullptr);
    SendMessageW(m_hEditDllPath, WM_SETFONT, (WPARAM)m_hFontMono, TRUE);

    m_hBtnBrowse = CreateWindowExW(0, L"BUTTON", L"...",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        x + cw - 34, y, 34, CONTROL_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_BTN_BROWSE, m_hInstance, nullptr);
    SendMessageW(m_hBtnBrowse, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    y += CONTROL_HEIGHT + 12;

    /* ── Action buttons row ─────────────────────────────── */
    int btnX = x + (cw - 3 * BUTTON_WIDTH - 20) / 2;

    m_hBtnInject = CreateWindowExW(0, L"BUTTON",
        L"\x25B6  Inject DLL",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX, y, BUTTON_WIDTH, BUTTON_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_BTN_INJECT, m_hInstance, nullptr);
    SendMessageW(m_hBtnInject, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);

    m_hBtnEject = CreateWindowExW(0, L"BUTTON",
        L"\x25A0  Eject DLL",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX + BUTTON_WIDTH + 10, y, BUTTON_WIDTH, BUTTON_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_BTN_EJECT, m_hInstance, nullptr);
    SendMessageW(m_hBtnEject, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);

    m_hBtnSettings = CreateWindowExW(0, L"BUTTON",
        L"\x2699  Settings",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        btnX + 2 * (BUTTON_WIDTH + 10), y, BUTTON_WIDTH, BUTTON_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_BTN_SETTINGS, m_hInstance, nullptr);
    SendMessageW(m_hBtnSettings, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    y += BUTTON_HEIGHT + 10;

    /* ── Statistics row ─────────────────────────────────── */
    int statW = (cw - 20) / 3;

    m_hStaticHooks = CreateWindowExW(0, L"STATIC",
        L"Hooks: 0",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        x, y, statW, 20,
        m_hWnd, (HMENU)(UINT_PTR)IDC_STATIC_HOOKS, m_hInstance, nullptr);
    SendMessageW(m_hStaticHooks, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);

    m_hStaticCalls = CreateWindowExW(0, L"STATIC",
        L"Total Calls: 0",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        x + statW + 10, y, statW, 20,
        m_hWnd, (HMENU)(UINT_PTR)IDC_STATIC_CALLS, m_hInstance, nullptr);
    SendMessageW(m_hStaticCalls, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);

    m_hStaticDropped = CreateWindowExW(0, L"STATIC",
        L"Dropped: 0",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        x + 2 * (statW + 10), y, statW, 20,
        m_hWnd, (HMENU)(UINT_PTR)IDC_STATIC_DROPPED, m_hInstance, nullptr);
    SendMessageW(m_hStaticDropped, WM_SETFONT, (WPARAM)m_hFontBold, TRUE);

    y += 28;

    /* ── ListView (trace data) ──────────────────────────── */
    m_hListView = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER |
        LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_NOSORTHEADER,
        x, y, cw, LISTVIEW_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_LISTVIEW_TRACE, m_hInstance, nullptr);

    SendMessageW(m_hListView, WM_SETFONT, (WPARAM)m_hFontMono, TRUE);
    ListView_SetExtendedListViewStyle(m_hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    InitListView();

    y += LISTVIEW_HEIGHT + 8;

    /* ── Log area ───────────────────────────────────────── */
    m_hEditLog = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        x, y, cw, LOG_HEIGHT,
        m_hWnd, (HMENU)(UINT_PTR)IDC_EDIT_LOG, m_hInstance, nullptr);
    SendMessageW(m_hEditLog, WM_SETFONT, (WPARAM)m_hFontMono, TRUE);

    y += LOG_HEIGHT + 8;

    /* ── Bottom buttons ─────────────────────────────────── */
    int bbW = 120;
    int bbX = x + (cw - 3 * bbW - 20) / 2;

    m_hBtnExport = CreateWindowExW(0, L"BUTTON",
        L"\xD83D\xDCBE Export CSV",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        bbX, y, bbW, CONTROL_HEIGHT + 4,
        m_hWnd, (HMENU)(UINT_PTR)IDC_BTN_EXPORT, m_hInstance, nullptr);
    SendMessageW(m_hBtnExport, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    m_hBtnClear = CreateWindowExW(0, L"BUTTON",
        L"\xD83D\xDDD1 Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        bbX + bbW + 10, y, bbW, CONTROL_HEIGHT + 4,
        m_hWnd, (HMENU)(UINT_PTR)IDC_BTN_CLEAR, m_hInstance, nullptr);
    SendMessageW(m_hBtnClear, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    m_hBtnPause = CreateWindowExW(0, L"BUTTON",
        L"\x23F8 Pause",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        bbX + 2 * (bbW + 10), y, bbW, CONTROL_HEIGHT + 4,
        m_hWnd, (HMENU)(UINT_PTR)IDC_BTN_PAUSE, m_hInstance, nullptr);
    SendMessageW(m_hBtnPause, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    y += CONTROL_HEIGHT + 12;

    /* ── Status bar ─────────────────────────────────────── */
    m_hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, L"",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        m_hWnd, (HMENU)(UINT_PTR)IDT_STATUS_TIMER, m_hInstance, nullptr);
    SendMessageW(m_hStatusBar, WM_SETFONT, (WPARAM)m_hFont, TRUE);

    /* Set status bar parts */
    int parts[] = { 250, 450, -1 };
    SendMessageW(m_hStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
    SendMessageW(m_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L" Ready");
    SendMessageW(m_hStatusBar, SB_SETTEXTW, 1, (LPARAM)L" DLL: Not connected");
    SendMessageW(m_hStatusBar, SB_SETTEXTW, 2, (LPARAM)L" Uptime: 0s");
}

/* ================================================================== */
/*  Initialize ListView Columns                                        */
/* ================================================================== */

void MainWindow::InitListView()
{
    struct ColumnDef {
        const wchar_t* name;
        int width;
        int fmt;
    };

    ColumnDef columns[] = {
        { L"Offset",     90, LVCFMT_LEFT   },
        { L"Address",    90, LVCFMT_LEFT   },
        { L"Name",      180, LVCFMT_LEFT   },
        { L"Calls/sec",  80, LVCFMT_RIGHT  },
        { L"Total",     100, LVCFMT_RIGHT  },
        { L"Thread",     70, LVCFMT_RIGHT  },
    };

    for (int i = 0; i < 6; ++i) {
        LVCOLUMNW col = {};
        col.mask    = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
        col.fmt     = columns[i].fmt;
        col.cx      = columns[i].width;
        col.pszText = const_cast<wchar_t*>(columns[i].name);
        col.iSubItem = i;
        ListView_InsertColumn(m_hListView, i, &col);
    }
}

/* ================================================================== */
/*  Apply Dark Theme                                                   */
/* ================================================================== */

void MainWindow::ApplyDarkTheme()
{
    /* Set ListView colors */
    ListView_SetBkColor(m_hListView, CLR_BG_LISTVIEW);
    ListView_SetTextBkColor(m_hListView, CLR_BG_LISTVIEW);
    ListView_SetTextColor(m_hListView, CLR_TEXT);

    /* Try to apply dark scrollbar theme */
    SetWindowTheme(m_hListView, L"DarkMode_Explorer", nullptr);
    SetWindowTheme(m_hEditLog, L"DarkMode_CFD", nullptr);
    SetWindowTheme(m_hEditProcess, L"DarkMode_CFD", nullptr);
    SetWindowTheme(m_hEditDllPath, L"DarkMode_CFD", nullptr);
}

/* ================================================================== */
/*  Resize Handler                                                     */
/* ================================================================== */

void MainWindow::OnResize(int width, int height)
{
    if (!m_hListView) return;

    int cw = width - MARGIN * 2;

    /* Reposition ListView */
    RECT rcLV;
    GetWindowRect(m_hListView, &rcLV);
    POINT ptLV = { rcLV.left, rcLV.top };
    ScreenToClient(m_hWnd, &ptLV);
    int lvH = height - ptLV.y - LOG_HEIGHT - 70;
    if (lvH < 100) lvH = 100;
    MoveWindow(m_hListView, MARGIN, ptLV.y, cw, lvH, TRUE);

    /* Reposition log */
    int logY = ptLV.y + lvH + 8;
    int logH = height - logY - 60;
    if (logH < 40) logH = 40;
    MoveWindow(m_hEditLog, MARGIN, logY, cw, logH, TRUE);

    /* Status bar auto-sizes */
    SendMessageW(m_hStatusBar, WM_SIZE, 0, 0);
}

/* ================================================================== */
/*  Command Handlers                                                   */
/* ================================================================== */

void MainWindow::OnFindProcess()
{
    char procName[256];
    GetWindowTextA(m_hEditProcess, procName, sizeof(procName));

    if (procName[0] == '\0') {
        AppendLog("[!] Enter a process name first.\r\n");
        return;
    }

    AppendLog("[*] Searching for %s...\r\n", procName);

    DWORD pid = 0;
    if (m_onFind) {
        pid = m_onFind(procName);
    }

    if (pid != 0) {
        m_targetPid = pid;
        m_attached = true;

        wchar_t buf[128];
        swprintf_s(buf, L"\x25CF Attached");
        SetWindowTextW(m_hStaticStatus, buf);

        swprintf_s(buf, L"PID: %d", pid);
        SetWindowTextW(m_hStaticPid, buf);

        AppendLog("[+] Found %s (PID: %d)\r\n", procName, pid);
        SendMessageW(m_hStatusBar, SB_SETTEXTW, 0,
                      (LPARAM)L" Attached to main.exe");
    } else {
        m_attached = false;
        m_targetPid = 0;
        SetWindowTextW(m_hStaticStatus, L"\x25CF Not found");
        SetWindowTextW(m_hStaticPid, L"PID: ---");
        AppendLog("[-] %s not found. Is the game running?\r\n", procName);
    }
}

void MainWindow::OnInjectDLL()
{
    if (!m_attached || m_targetPid == 0) {
        AppendLog("[!] Not attached to any process. Click Find first.\r\n");
        return;
    }

    wchar_t dllPath[MAX_PATH];
    GetWindowTextW(m_hEditDllPath, dllPath, MAX_PATH);
    m_dllPath = dllPath;

    AppendLog("[*] Injecting DLL into PID %d...\r\n", m_targetPid);

    std::string errorMsg;
    if (m_onInject) {
        errorMsg = m_onInject(m_targetPid, m_dllPath);
    }

    if (errorMsg.empty()) {
        AppendLog("[+] DLL injected successfully!\r\n");
        AppendLog("[*] Starting base: offsets=0, functions=0, variables=0, modules=0\r\n");
        AppendLog("[*] Database will be populated from main.exe scan...\r\n");
        AppendLog("[*] Real-time monitoring of all game actions enabled.\r\n");
        SendMessageW(m_hStatusBar, SB_SETTEXTW, 1,
                      (LPARAM)L" DLL: Injected - Scanning");
    } else {
        AppendLog("[-] Injection failed: %s\r\n", errorMsg.c_str());
        AppendLog("[i] See injection_log.txt for detailed diagnostics.\r\n");
    }
}

void MainWindow::OnEjectDLL()
{
    if (m_targetPid == 0) {
        AppendLog("[!] No target process.\r\n");
        return;
    }

    AppendLog("[*] Ejecting DLL from PID %d...\r\n", m_targetPid);

    bool ok = false;
    if (m_onEject) {
        ok = m_onEject(m_targetPid);
    }

    if (ok) {
        AppendLog("[+] DLL ejected.\r\n");
        SendMessageW(m_hStatusBar, SB_SETTEXTW, 1,
                      (LPARAM)L" DLL: Not connected");
    } else {
        AppendLog("[-] Eject failed.\r\n");
    }
}

void MainWindow::OnBrowseDLL()
{
    wchar_t filePath[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = m_hWnd;
    ofn.lpstrFilter  = L"DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.lpstrFile    = filePath;
    ofn.nMaxFile     = MAX_PATH;
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        SetWindowTextW(m_hEditDllPath, filePath);
        m_dllPath = filePath;
    }
}

void MainWindow::OnExportCSV()
{
    wchar_t filePath[MAX_PATH] = L"MuTracker_Export.csv";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = m_hWnd;
    ofn.lpstrFilter   = L"CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrFile     = filePath;
    ofn.nMaxFile      = MAX_PATH;
    ofn.Flags         = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt   = L"csv";

    if (GetSaveFileNameW(&ofn)) {
        if (m_traceViewer.ExportCSV(filePath)) {
            AppendLog("[+] Exported to %ls\r\n", filePath);
        } else {
            AppendLog("[-] Export failed.\r\n");
        }
    }
}

void MainWindow::OnClearLog()
{
    SetWindowTextW(m_hEditLog, L"");
    m_traceViewer.Clear();
    ListView_DeleteAllItems(m_hListView);
    AppendLog("[*] Cleared.\r\n");
}

void MainWindow::OnPauseResume()
{
    m_paused = !m_paused;
    SetWindowTextW(m_hBtnPause,
                    m_paused ? L"\x25B6 Resume" : L"\x23F8 Pause");
    AppendLog(m_paused ? "[*] Paused.\r\n" : "[*] Resumed.\r\n");
}

void MainWindow::OnSettings()
{
    MessageBoxW(m_hWnd,
        L"Settings dialog will be available in a future version.\n\n"
        L"Edit config.json manually for now.",
        L"Settings", MB_OK | MB_ICONINFORMATION);
}

/* ================================================================== */
/*  Timer-based Update                                                 */
/* ================================================================== */

void MainWindow::OnUpdateTimer()
{
    /* Try to connect and update */
    m_traceViewer.Update();

    if (m_traceViewer.IsConnected()) {
        auto stats = m_traceViewer.GetStats();

        /* Update statistics labels */
        wchar_t buf[128];
        swprintf_s(buf, L"Hooks: %u | Funcs: %u | Mods: %u | Vars: %u",
                    stats.hookedFunctions,
                    stats.functionCount,
                    stats.moduleCount,
                    stats.variableCount);
        SetWindowTextW(m_hStaticHooks, buf);

        swprintf_s(buf, L"Total Calls: %llu | Changed Vars: %u",
                    static_cast<unsigned long long>(stats.totalCalls),
                    stats.changedVariables);
        SetWindowTextW(m_hStaticCalls, buf);

        swprintf_s(buf, L"Dropped: %u", stats.droppedRecords);
        SetWindowTextW(m_hStaticDropped, buf);

        /* Update status bar */
        SendMessageW(m_hStatusBar, SB_SETTEXTW, 1,
            stats.dllConnected
                ? (LPARAM)L" DLL: Connected"
                : (LPARAM)L" DLL: Waiting...");

        swprintf_s(buf, L" Uptime: %llu s | Modules: %u | Vars: %u",
                    static_cast<unsigned long long>(stats.uptimeMs / 1000),
                    stats.moduleCount,
                    stats.variableCount);
        SendMessageW(m_hStatusBar, SB_SETTEXTW, 2, (LPARAM)buf);

        /* Update ListView */
        UpdateListView();
    }
}

void MainWindow::UpdateListView()
{
    auto entries = m_traceViewer.GetEntries();

    /* Update or add items */
    int currentCount = ListView_GetItemCount(m_hListView);
    int newCount = static_cast<int>(entries.size());

    /* If count changed significantly, rebuild */
    int diff = newCount - currentCount;
    if (diff > 10 || diff < -10) {
        ListView_DeleteAllItems(m_hListView);
        currentCount = 0;
    }

    for (int i = 0; i < newCount && i < 500; ++i) {
        const auto& e = entries[i];
        wchar_t buf[256];

        if (i >= currentCount) {
            /* Insert new item */
            LVITEMW item = {};
            item.mask    = LVIF_TEXT;
            item.iItem   = i;
            item.iSubItem = 0;
            swprintf_s(buf, L"0x%08X", static_cast<uint32_t>(e.offset));
            item.pszText = buf;
            ListView_InsertItem(m_hListView, &item);
        } else {
            /* Update existing */
            swprintf_s(buf, L"0x%08X", static_cast<uint32_t>(e.offset));
            ListView_SetItemText(m_hListView, i, 0, buf);
        }

        /* Address */
        swprintf_s(buf, L"0x%08X", static_cast<uint32_t>(e.address));
        ListView_SetItemText(m_hListView, i, 1, buf);

        /* Name */
        wchar_t wname[128];
        MultiByteToWideChar(CP_ACP, 0, e.name.c_str(), -1,
                             wname, 128);
        ListView_SetItemText(m_hListView, i, 2, wname);

        /* Calls/sec */
        swprintf_s(buf, L"%u/s", e.callsPerSec);
        ListView_SetItemText(m_hListView, i, 3, buf);

        /* Total */
        swprintf_s(buf, L"%llu",
                    static_cast<unsigned long long>(e.totalCalls));
        ListView_SetItemText(m_hListView, i, 4, buf);

        /* Thread */
        swprintf_s(buf, L"%u", e.threadId);
        ListView_SetItemText(m_hListView, i, 5, buf);
    }

    /* Remove extra items if list shrunk */
    while (ListView_GetItemCount(m_hListView) > newCount) {
        ListView_DeleteItem(m_hListView,
                             ListView_GetItemCount(m_hListView) - 1);
    }
}

void MainWindow::UpdateStatusBar()
{
    /* Already handled in OnUpdateTimer */
}

/* ================================================================== */
/*  Custom Drawing                                                     */
/* ================================================================== */

void MainWindow::PaintBackground(HDC hdc, const RECT& rc)
{
    /* Separator lines */
    RECT rcClient;
    GetClientRect(m_hWnd, &rcClient);

    HPEN hPen = CreatePen(PS_SOLID, 1, CLR_SEPARATOR);
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);

    /* Draw separator above buttons row */
    RECT rcBtn;
    GetWindowRect(m_hBtnInject, &rcBtn);
    POINT ptBtn = { rcBtn.left, rcBtn.top };
    ScreenToClient(m_hWnd, &ptBtn);
    MoveToEx(hdc, MARGIN, ptBtn.y - 5, nullptr);
    LineTo(hdc, rcClient.right - MARGIN, ptBtn.y - 5);

    /* Draw separator above stats */
    RECT rcStat;
    GetWindowRect(m_hStaticHooks, &rcStat);
    POINT ptStat = { rcStat.left, rcStat.top };
    ScreenToClient(m_hWnd, &ptStat);
    MoveToEx(hdc, MARGIN, ptStat.y - 5, nullptr);
    LineTo(hdc, rcClient.right - MARGIN, ptStat.y - 5);

    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);
}

void MainWindow::DrawSeparator(HDC hdc, int y, int width)
{
    HPEN hPen = CreatePen(PS_SOLID, 1, CLR_SEPARATOR);
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
    MoveToEx(hdc, MARGIN, y, nullptr);
    LineTo(hdc, width - MARGIN, y);
    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);
}

LRESULT MainWindow::OnCtlColorStatic(HDC hdc, HWND hCtl)
{
    SetBkMode(hdc, TRANSPARENT);
    SetBkColor(hdc, CLR_BG_MAIN);

    /* Status indicator coloring */
    if (hCtl == m_hStaticStatus) {
        SetTextColor(hdc, m_attached ? CLR_GREEN : CLR_YELLOW);
    } else if (hCtl == m_hStaticHooks || hCtl == m_hStaticCalls) {
        SetTextColor(hdc, CLR_ACCENT);
    } else if (hCtl == m_hStaticDropped) {
        SetTextColor(hdc, CLR_TEXT_DIM);
    } else {
        SetTextColor(hdc, CLR_TEXT);
    }

    return reinterpret_cast<LRESULT>(m_hBrushBg);
}

LRESULT MainWindow::OnCtlColorEdit(HDC hdc, HWND hCtl)
{
    SetBkMode(hdc, OPAQUE);

    if (hCtl == m_hEditLog) {
        SetTextColor(hdc, CLR_GREEN);
        SetBkColor(hdc, CLR_BG_LOG);
        return reinterpret_cast<LRESULT>(m_hBrushLog);
    }

    SetTextColor(hdc, CLR_TEXT);
    SetBkColor(hdc, CLR_BG_EDIT);
    return reinterpret_cast<LRESULT>(m_hBrushEdit);
}

LRESULT MainWindow::OnCustomDrawListView(LPNMLVCUSTOMDRAW lpcd)
{
    switch (lpcd->nmcd.dwDrawStage) {

    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;

    case CDDS_ITEMPREPAINT:
        return CDRF_NOTIFYSUBITEMDRAW;

    case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
        /* Alternate row colors */
        if (lpcd->nmcd.dwItemSpec % 2 == 0) {
            lpcd->clrTextBk = CLR_BG_LISTVIEW;
        } else {
            lpcd->clrTextBk = RGB(40, 40, 50);
        }

        /* Color columns differently */
        switch (lpcd->iSubItem) {
        case 0: /* Offset */
        case 1: /* Address */
            lpcd->clrText = CLR_ACCENT;
            break;
        case 2: /* Name */
            lpcd->clrText = CLR_TEXT;
            break;
        case 3: /* Calls/sec */
            lpcd->clrText = CLR_GREEN;
            break;
        case 4: /* Total */
            lpcd->clrText = CLR_YELLOW;
            break;
        default:
            lpcd->clrText = CLR_TEXT_DIM;
            break;
        }

        return CDRF_NEWFONT;
    }
    }

    return CDRF_DODEFAULT;
}

/* ================================================================== */
/*  Log Append                                                         */
/* ================================================================== */

void MainWindow::AppendLog(const char* format, ...)
{
    if (!m_hEditLog) return;

    char buf[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    buf[sizeof(buf) - 1] = '\0';

    /* Convert to wide string */
    wchar_t wbuf[1024];
    MultiByteToWideChar(CP_ACP, 0, buf, -1, wbuf, 1024);

    /* Append to edit control */
    int len = GetWindowTextLengthW(m_hEditLog);
    SendMessageW(m_hEditLog, EM_SETSEL, len, len);
    SendMessageW(m_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)wbuf);

    /* Auto-scroll to bottom */
    SendMessageW(m_hEditLog, EM_SCROLLCARET, 0, 0);
}

} /* namespace MuTracker */
