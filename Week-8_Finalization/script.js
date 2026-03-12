// 🔐 Protect Chat Page
const token = localStorage.getItem("token");

if (!token) {
    window.location.href = "login.html";
}

// 🚀 Send Message Function
function sendMessage() {

    const inputField = document.getElementById("userInput");
    const userInput = inputField.value.trim();

    // Prevent empty messages
    if (!userInput) {
        return;
    }

    const chatBox = document.getElementById("chatBox");

    // Show user message immediately
    chatBox.innerHTML += `
        <p><strong>You:</strong> ${userInput}</p>
    `;

    // Send request to backend
    fetch("http://localhost:5000/chat", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token
        },
        body: JSON.stringify({
            symptom: userInput
        })
    })
    .then(response => {

        if (!response.ok) {
            throw new Error("Server error");
        }

        return response.json();
    })
    .then(data => {

        // Safe AI response
        const aiReply = data.reply || data.message || "AI service unavailable.";

        chatBox.innerHTML += `
            <p><strong>AI:</strong> ${aiReply}</p>
        `;

        // Auto scroll
        chatBox.scrollTop = chatBox.scrollHeight;

    })
    .catch(error => {

        console.error("Error:", error);

        chatBox.innerHTML += `
            <p><strong>AI:</strong> Server error. Please try again.</p>
        `;

        chatBox.scrollTop = chatBox.scrollHeight;
    });

    // Clear input box
    inputField.value = "";
}

// ⌨️ Send message when pressing Enter
document.getElementById("userInput").addEventListener("keypress", function(event) {
    if (event.key === "Enter") {
        sendMessage();
    }
});

// 🚪 Logout function
function logout() {
    localStorage.removeItem("token");
    window.location.href = "login.html";
}