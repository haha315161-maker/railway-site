document.addEventListener("DOMContentLoaded", () => {

  // ======================================================
  // CSRF
  // ======================================================

  let csrfToken = "";

  async function loadCsrfToken() {

    const response = await fetch(
      "/api/csrf-token",
      {
        method: "GET",
        credentials: "same-origin"
      }
    );

    const result = await response.json();

    if (
      !response.ok ||
      !result.success ||
      !result.csrfToken
    ) {
      throw new Error("CSRF token alınamadı.");
    }

    csrfToken = result.csrfToken;

    return csrfToken;
  }


  async function csrfFetch(url, options = {}) {

    if (!csrfToken) {
      await loadCsrfToken();
    }

    return fetch(url, {
      ...options,

      credentials: "same-origin",

      headers: {
        ...(options.headers || {}),

        "Content-Type": "application/json",

        "X-CSRF-Token": csrfToken
      }
    });
  }


  // ======================================================
  // KAYIT
  // ======================================================

  const registerForm =
    document.getElementById("registerForm");

  if (registerForm) {

    registerForm.addEventListener(
      "submit",
      async (e) => {

        e.preventDefault();

        const message =
          document.getElementById("message");

        const button =
          document.getElementById("registerButton");

        const formData =
          new FormData(registerForm);

        const data = {
          username: formData.get("username"),
          email: formData.get("email"),
          password: formData.get("password")
        };

        if (button) {
          button.disabled = true;
          button.textContent = "Kayıt olunuyor...";
        }

        if (message) {
          message.className = "";
          message.textContent = "Lütfen bekle...";
        }

        try {

          await loadCsrfToken();

          const response = await csrfFetch(
            "/api/register",
            {
              method: "POST",
              body: JSON.stringify(data)
            }
          );

          const result = await response.json();

          if (!result.success) {

            if (message) {
              message.className = "error";
              message.textContent =
                result.message ||
                "Kayıt başarısız.";
            }

            if (button) {
              button.disabled = false;
              button.textContent = "Kayıt Ol";
            }

            return;
          }

          if (
            result.csrfRefresh &&
            result.csrfToken
          ) {
            csrfToken = result.csrfToken;
          }

          if (message) {
            message.className = "success";
            message.textContent = "Kayıt başarılı!";
          }

          setTimeout(() => {

            window.location.href =
              result.redirect ||
              "/profile.html";

          }, 700);

        } catch (error) {

          console.error(
            "REGISTER ERROR:",
            error
          );

          if (message) {
            message.className = "error";
            message.textContent =
              "Sunucuya bağlanılamadı.";
          }

          if (button) {
            button.disabled = false;
            button.textContent = "Kayıt Ol";
          }
        }
      }
    );
  }


  // ======================================================
  // GİRİŞ
  // ======================================================

  const loginForm =
    document.getElementById("loginForm");

  if (loginForm) {

    loginForm.addEventListener(
      "submit",
      async (e) => {

        e.preventDefault();

        const message =
          document.getElementById("message");

        const formData =
          new FormData(loginForm);

        const data = {
          email: formData.get("email"),
          password: formData.get("password")
        };

        try {

          await loadCsrfToken();

          const response = await csrfFetch(
            "/api/login",
            {
              method: "POST",
              body: JSON.stringify(data)
            }
          );

          const result =
            await response.json();

          if (!result.success) {

            if (message) {
              message.className = "error";
              message.textContent =
                result.message ||
                "Giriş başarısız.";
            }

            return;
          }

          if (
            result.csrfRefresh &&
            result.csrfToken
          ) {
            csrfToken = result.csrfToken;
          }

          if (message) {
            message.className = "success";
            message.textContent =
              "Giriş başarılı!";
          }

          setTimeout(() => {

            window.location.href =
              result.redirect ||
              "/profile.html";

          }, 700);

        } catch (error) {

          console.error(
            "LOGIN ERROR:",
            error
          );

          if (message) {
            message.className = "error";
            message.textContent =
              "Sunucuya bağlanılamadı.";
          }
        }
      }
    );
  }


  // ======================================================
  // ŞİFRE SIFIRLAMA MAİLİ
  // ======================================================

  const forgotForm =
    document.getElementById("forgotForm");

  if (forgotForm) {

    forgotForm.addEventListener(
      "submit",
      async (e) => {

        e.preventDefault();

        const message =
          document.getElementById("message");

        const formData =
          new FormData(forgotForm);

        const email =
          formData.get("email");

        if (message) {
          message.className = "";
          message.textContent =
            "Kod gönderiliyor...";
        }

        try {

          const response =
            await csrfFetch(
              "/api/forgot-password",
              {
                method: "POST",

                body: JSON.stringify({
                  email
                })
              }
            );

          const result =
            await response.json();

          if (!result.success) {

            if (message) {
              message.className = "error";
              message.textContent =
                result.message ||
                "İşlem başarısız.";
            }

            return;
          }

          if (message) {
            message.className = "success";
            message.textContent =
              "Kod gönderildi. E-postanı kontrol et.";
          }

          setTimeout(() => {

            if (result.redirect) {
              window.location.href =
                result.redirect;
            }

          }, 1200);

        } catch (error) {

          console.error(
            "FORGOT PASSWORD ERROR:",
            error
          );

          if (message) {
            message.className = "error";
            message.textContent =
              "Sunucuya bağlanılamadı.";
          }
        }
      }
    );
  }


  // ======================================================
  // KOD DOĞRULAMA
  // ======================================================

  const verifyCodeForm =
    document.getElementById(
      "verifyCodeForm"
    );

  if (verifyCodeForm) {

    verifyCodeForm.addEventListener(
      "submit",
      async (e) => {

        e.preventDefault();

        const message =
          document.getElementById("message");

        const formData =
          new FormData(verifyCodeForm);

        const code =
          formData.get("code");

        try {

          const response =
            await csrfFetch(
              "/api/verify-reset-code",
              {
                method: "POST",

                body: JSON.stringify({
                  code
                })
              }
            );

          const result =
            await response.json();

          if (!result.success) {

            if (message) {
              message.className = "error";
              message.textContent =
                result.message ||
                "Kod geçersiz.";
            }

            return;
          }

          if (message) {
            message.className = "success";
            message.textContent =
              "Kod doğru.";
          }

          verifyCodeForm.style.display =
            "none";

          const newPasswordArea =
            document.getElementById(
              "newPasswordArea"
            );

          if (newPasswordArea) {
            newPasswordArea.style.display =
              "block";
          }

        } catch (error) {

          console.error(
            "VERIFY CODE ERROR:",
            error
          );

          if (message) {
            message.className = "error";
            message.textContent =
              "Sunucuya bağlanılamadı.";
          }
        }
      }
    );
  }


  // ======================================================
  // YENİ ŞİFRE
  // ======================================================

  const resetPasswordForm =
    document.getElementById(
      "resetPasswordForm"
    );

  if (resetPasswordForm) {

    resetPasswordForm.addEventListener(
      "submit",
      async (e) => {

        e.preventDefault();

        const message =
          document.getElementById("message");

        const formData =
          new FormData(resetPasswordForm);

        const password =
          formData.get("password");

        const passwordConfirm =
          formData.get("passwordConfirm");

        if (password !== passwordConfirm) {

          if (message) {
            message.className = "error";
            message.textContent =
              "Şifreler aynı değil.";
          }

          return;
        }

        try {

          const response =
            await csrfFetch(
              "/api/reset-password",
              {
                method: "POST",

                body: JSON.stringify({
                  password
                })
              }
            );

          const result =
            await response.json();

          if (!result.success) {

            if (message) {
              message.className = "error";
              message.textContent =
                result.message ||
                "Şifre değiştirilemedi.";
            }

            return;
          }

          if (message) {
            message.className = "success";
            message.textContent =
              "Şifren değiştirildi!";
          }

          setTimeout(() => {

            window.location.href =
              result.redirect ||
              "/login.html";

          }, 1200);

        } catch (error) {

          console.error(
            "RESET PASSWORD ERROR:",
            error
          );

          if (message) {
            message.className = "error";
            message.textContent =
              "Sunucuya bağlanılamadı.";
          }
        }
      }
    );
  }


  // ======================================================
  // DASHBOARD / PROFİL
  // ======================================================

  async function loadDashboard() {

    try {

      const response =
        await fetch(
          "/api/dashboard",
          {
            credentials: "same-origin"
          }
        );

      if (response.status === 401) {

        window.location.href =
          "/login.html";

        return;
      }

      const data =
        await response.json();

      if (!data.success || !data.user) {

        await loadProfile();

        return;
      }

      const user =
        data.user;

      setUserData(user);

      const statUser =
        document.getElementById("statUser");

      if (statUser) {
        statUser.textContent =
          user.username;
      }

      const statMessages =
        document.getElementById(
          "statMessages"
        );

      if (
        statMessages &&
        data.stats
      ) {
        statMessages.textContent =
          data.stats.messageCount ?? 0;
      }

      const statReplies =
        document.getElementById(
          "statReplies"
        );

      if (
        statReplies &&
        data.stats
      ) {
        statReplies.textContent =
          data.stats.supportReplies ?? 0;
      }

      await checkAdmin();

    } catch (error) {

      console.error(
        "DASHBOARD ERROR:",
        error
      );

      await loadProfile();
    }
  }


  async function loadProfile() {

    try {

      const response =
        await fetch(
          "/api/me",
          {
            credentials: "same-origin"
          }
        );

      if (!response.ok) {

        window.location.href =
          "/login.html";

        return;
      }

      const result =
        await response.json();

      if (
        !result.success ||
        !result.user
      ) {

        window.location.href =
          "/login.html";

        return;
      }

      setUserData(result.user);

      await checkAdmin();

    } catch (error) {

      console.error(
        "PROFILE ERROR:",
        error
      );

      window.location.href =
        "/login.html";
    }
  }


  function setUserData(user) {

    const username =
      document.getElementById("username");

    if (username) {
      username.textContent =
        user.username;
    }

    const profileUsername =
      document.getElementById(
        "profileUsername"
      );

    if (profileUsername) {
      profileUsername.textContent =
        user.username;
    }

    const profileEmail =
      document.getElementById(
        "profileEmail"
      );

    if (profileEmail) {
      profileEmail.textContent =
        user.email;
    }

    const profileDate =
      document.getElementById(
        "profileDate"
      );

    if (profileDate && user.created_at) {

      profileDate.textContent =
        new Date(
          user.created_at
        ).toLocaleDateString("tr-TR");
    }

    const profileCreated =
      document.getElementById(
        "profileCreated"
      );

    if (profileCreated && user.created_at) {

      profileCreated.textContent =
        new Date(
          user.created_at
        ).toLocaleString("tr-TR");
    }

    const avatar =
      document.getElementById("avatar");

    if (avatar && user.username) {

      avatar.textContent =
        user.username
          .charAt(0)
          .toUpperCase();
    }
  }


  // ======================================================
  // ADMIN KONTROLÜ
  // ======================================================

  async function checkAdmin() {

    const adminButton =
      document.getElementById(
        "adminButton"
      );

    if (!adminButton) {
      return;
    }

    try {

      const response =
        await fetch(
          "/api/admin/check",
          {
            credentials: "same-origin"
          }
        );

      if (!response.ok) {
        return;
      }

      const data =
        await response.json();

      if (
        data.success &&
        data.isAdmin === true
      ) {

        adminButton.style.display =
          "block";
      }

    } catch (error) {

      console.error(
        "ADMIN CHECK ERROR:",
        error
      );
    }
  }


  // ======================================================
  // SECTION DEĞİŞTİR
  // ======================================================

  window.showSection = function (
    id,
    button
  ) {

    document
      .querySelectorAll(".section")
      .forEach(section => {

        section.classList.remove(
          "active"
        );

      });

    document
      .querySelectorAll(".nav button")
      .forEach(btn => {

        btn.classList.remove(
          "active"
        );

      });

    const section =
      document.getElementById(id);

    if (section) {
      section.classList.add(
        "active"
      );
    }

    if (button) {
      button.classList.add(
        "active"
      );
    }

    if (id === "support") {
      loadMessages();
    }
  };


  // ======================================================
  // DESTEK MESAJLARINI GETİR
  // ======================================================

  async function loadMessages() {

    const box =
      document.getElementById(
        "messages"
      );

    if (!box) {
      return;
    }

    try {

      const response =
        await fetch(
          "/api/support/messages",
          {
            credentials: "same-origin"
          }
        );

      if (response.status === 401) {

        window.location.href =
          "/login.html";

        return;
      }

      const data =
        await response.json();

      if (
        !data.success ||
        !Array.isArray(data.messages) ||
        data.messages.length === 0
      ) {

        box.innerHTML = `
          <div class="empty">
            Henüz destek mesajın yok.
          </div>
        `;

        return;
      }

      box.innerHTML = "";

      data.messages.forEach(message => {

        const div =
          document.createElement(
            "div"
          );

        div.className =
          "message " +
          (
            message.sender === "admin"
              ? "admin"
              : "user"
          );

        const text =
          document.createElement(
            "div"
          );

        text.textContent =
          message.message;

        const date =
          document.createElement(
            "small"
          );

        if (message.created_at) {

          date.textContent =
            new Date(
              message.created_at
            ).toLocaleString(
              "tr-TR"
            );
        }

        div.appendChild(text);
        div.appendChild(date);

        box.appendChild(div);
      });

      box.scrollTop =
        box.scrollHeight;

    } catch (error) {

      console.error(
        "LOAD MESSAGES ERROR:",
        error
      );

      box.innerHTML = `
        <div class="empty">
          Mesajlar yüklenemedi.
        </div>
      `;
    }
  }


  // ======================================================
  // DESTEK MESAJI GÖNDER
  // ======================================================

  window.sendSupportMessage =
    async function () {
const supportInput =
  document.getElementById("supportInput");

if (supportInput) {

  supportInput.addEventListener(
    "keydown",
    (e) => {

      if (
        e.key === "Enter" &&
        !e.shiftKey
      ) {

        e.preventDefault();

        sendSupportMessage();
      }

    }
  );
}

      const input =
        document.getElementById(
          "supportInput"
        );

      if (!input) {
        return;
      }

      const message =
        input.value.trim();

      if (!message) {
        return;
      }

      try {

        const response =
          await csrfFetch(
            "/api/support/messages",
            {
              method: "POST",

              body: JSON.stringify({
                message
              })
            }
          );

        if (response.status === 401) {

          window.location.href =
            "/login.html";

          return;
        }

        const data =
          await response.json();

        if (!data.success) {

          alert(
            data.message ||
            "Mesaj gönderilemedi."
          );

          return;
        }

        input.value = "";

        await loadMessages();

        await loadDashboard();

      } catch (error) {

        console.error(
          "SEND SUPPORT ERROR:",
          error
        );

        alert(
          "Mesaj gönderilirken hata oluştu."
        );
      }
      
    };


  // ======================================================
  // ÇIKIŞ
  // ======================================================

  window.logout =
    async function () {

      try {

        await csrfFetch(
          "/api/logout",
          {
            method: "POST"
          }
        );

      } catch (error) {

        console.error(
          "LOGOUT ERROR:",
          error
        );
      }

      window.location.href = "/";
    };


  // ======================================================
  // SAYFA BAŞLANGICI
  // ======================================================

  const isDashboard =
    document.getElementById("home") ||
    document.getElementById("profile") ||
    document.getElementById("messages");

  if (isDashboard) {
    loadDashboard();
  }

  
});
