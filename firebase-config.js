// ============================================================================
// Firebase 設定檔
// 請至 Firebase Console → 專案設定 → 一般 → 你的應用程式，複製設定貼到下方。
// https://console.firebase.google.com/
// ============================================================================
export const firebaseConfig = {
　apiKey: "AIzaSyCc2PzNw3eTPQpv1JbQOGh32y2-P3NyQtE",
  authDomain: "health-1f.firebaseapp.com",
  projectId: "health-1f",
  storageBucket: "health-1f.firebasestorage.app",
  messagingSenderId: "841889312674",
  appId: "1:841889312674:web:8eaddd892563d8ba0accfb",
  measurementId: "G-SZ6WHZH25R"
};

// ============================================================================
// 應用程式設定
// ============================================================================
export const appConfig = {
  // 應用程式名稱（顯示在側邊欄與瀏覽器標籤）
  appName: "健康記事",

  // Firestore 集合名稱
  recordsCollection: "records",
  settingsCollection: "settings",

  // 密碼保護說明：
  // 密碼「雜湊」不會存在這個檔案裡，而是存在 Firestore 的
  // settings/access 文件中。第一次開啟網站時，系統會請你設定一組密碼，
  // 之後所有裝置都用同一組密碼登入（雜湊比對，密碼本身不會被儲存）。
  // 這是「避免外人隨意看到」等級的保護，不是銀行等級的安全機制，
  // 請勿存放身分證字號、健保卡號等高度敏感資料。
};
