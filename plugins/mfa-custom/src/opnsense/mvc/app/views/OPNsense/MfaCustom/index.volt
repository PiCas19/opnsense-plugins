<!-- index.volt aggiornato -->
<div class="content-box">
  <div class="row">
    <div class="col-md-12">
      <h2>{{ lang._('Two-Factor Authentication') }}</h2>
      <p>{{ lang._('Generate your QR code and verify it with your authenticator app.') }}</p>
    </div>
  </div>

  <!-- Generate QR Code + Reset -->
  <div class="mb-3">
    <button class="btn btn-info" id="genQR">{{ lang._('Generate QR Code') }}</button>
    <button class="btn btn-danger" id="resetQR">{{ lang._('Reset Secret') }}</button>
  </div>

  <div class="row" id="qrContainer" style="display: none; margin-top: 20px;">
    <div class="col-md-6">
      <img id="qrImage" alt="QR Code" />
      <p><strong>{{ lang._('Secret Key:') }}</strong> <span id="secretCode"></span></p>
    </div>
  </div>

  <!-- OTP Form -->
  <form id="otpForm" style="margin-top: 30px;">
    <div class="row">
      <div class="col-md-6">
        <div class="form-group">
          <label for="otp">{{ lang._('Enter OTP') }}</label>
          <input class="form-control" type="text" id="otp" name="otp" required />
        </div>
        <div id="status" class="text-danger mt-2"></div>
        <button type="submit" class="btn btn-primary">{{ lang._('Verify') }}</button>
      </div>
    </div>
  </form>
</div>

<script>
document.getElementById("genQR").addEventListener("click", function () {
  fetch("/api/mfacustom/generate", { method: "POST" })
    .then((resp) => resp.json())
    .then((data) => {
      if (data.status === "ok") {
        const url = `https://chart.googleapis.com/chart?cht=qr&chs=200x200&chl=${encodeURIComponent(data.otpauth_url)}`;
        document.getElementById("qrImage").src = url;
        document.getElementById("secretCode").innerText = data.secret;
        document.getElementById("qrContainer").style.display = "block";
      }
    });
});

document.getElementById("resetQR").addEventListener("click", function () {
  if (!confirm("{{ lang._('Are you sure you want to reset your MFA secret?') }}")) return;

  fetch("/api/mfacustom/reset", { method: "POST" })
    .then((resp) => resp.json())
    .then((data) => {
      alert(data.message || "Done");
      location.reload();
    });
});

document.getElementById("otpForm").addEventListener("submit", function (e) {
  e.preventDefault();
  const form = new FormData(e.target);
  fetch("/api/mfacustom/verify", {
    method: "POST",
    body: form,
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.status === "success") {
        window.location = "/";
      } else {
        document.getElementById("status").innerText = "{{ lang._('Invalid OTP code.') }}";
      }
    })
    .catch((error) => {
      document.getElementById("status").innerText = "{{ lang._('An error occurred.') }}";
    });
});
</script>