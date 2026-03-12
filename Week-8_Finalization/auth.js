// ---------------- LOGIN ----------------
const loginForm = document.getElementById("loginForm");

if (loginForm) {
    loginForm.addEventListener("submit", async function (e) {
        e.preventDefault();

        const email = document.getElementById("loginEmail").value;
        const password = document.getElementById("loginPassword").value;

        try {
            const response = await fetch("http://localhost:5000/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (response.ok) {
                // Save token
                localStorage.setItem("token", data.token);
                localStorage.setItem("userEmail", email); // Optional: Save email for display

                alert("Login successful!");
                
                // CHANGE THIS LINE: Redirect to chat.html instead of index.html
                window.location.href = "chat.html"; 
            } else {
                alert(data.message);
            }
        } catch (error) {
            console.error("Error:", error);
            alert("Server error. Please try again.");
        }
    });
}
// ---------------- REGISTER ----------------
const registerForm = document.getElementById("registerForm");

if (registerForm) {
    registerForm.addEventListener("submit", async function (e) {

        e.preventDefault();

        const name = document.getElementById("name").value;
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;
        const age = document.getElementById("age").value;
        const gender = document.getElementById("gender").value;

        try {

            const response = await fetch("http://localhost:5000/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    name,
                    email,
                    password,
                    age,
                    gender
                })
            });

            const data = await response.json();

            if (response.ok) {

                alert("Registration successful!");

                window.location.href = "login.html";

            } else {

                alert(data.message);

            }

        } catch (error) {

            console.error("Error:", error);
            alert("Server error. Please try again.");

        }

    });
}