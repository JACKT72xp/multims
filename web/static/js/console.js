document.addEventListener("DOMContentLoaded", function () {
    const prompt = 'multims> ';
    let ws;

    function connectWebSocket() {
        ws = new WebSocket('ws://localhost:9000/ws');

        ws.onopen = function () {
            console.log("WebSocket connection established");
            addToTerminal('Connected to server\n');
        };

        ws.onmessage = function (event) {
            const message = event.data.replace(/\n/g, '\r\n');
            addToTerminal(message + '\n');
            console.log("Message received: ", event.data);
        };

        ws.onerror = function (error) {
            console.log("WebSocket error: ", error);
        };

        ws.onclose = function (event) {
            console.log("WebSocket connection closed: ", event);
            addToTerminal('Connection closed. Attempting to reconnect...\n');
            setTimeout(connectWebSocket, 5000);
        };
    }

    connectWebSocket();

    function sendCommand(command) {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(command);
            console.log("Command sent: ", command);
        } else {
            console.log("WebSocket connection is not open");
            addToTerminal('Connection is not open. Trying to reconnect...\n');
            connectWebSocket();
        }
    }

    function addToTerminal(message) {
        const terminal = document.getElementById('terminal');
        terminal.value += message;
        terminal.scrollTop = terminal.scrollHeight;
    }

    const inputField = document.getElementById('input');
    const sendButton = document.getElementById('sendButton');
    sendButton.addEventListener('click', function () {
        const command = inputField.value.trim();
        if (command.length > 0) {
            addToTerminal(`${prompt}${command}\n`);
            sendCommand(command);
            updateHistory(command);
        }
        inputField.value = '';
    });

    inputField.addEventListener('keypress', function (event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            sendButton.click();
        }
    });

    function updateHistory(command) {
        const historyContainer = document.getElementById('command-history');
        const historyItem = document.createElement('li');
        historyItem.textContent = command;
        historyItem.addEventListener('click', function () {
            inputField.value = command;
        });
        historyContainer.appendChild(historyItem);
    }
});

document.getElementById('menu-toggle').addEventListener('click', function () {
    var menu = document.getElementById('menu');
    menu.classList.toggle('active');
});
