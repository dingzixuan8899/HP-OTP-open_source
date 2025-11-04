class MockSMSGateway:
    def __init__(self):
        self.inbox = {}  # Key: phone number, Value: list of messages (FIFO)

    def send_sms(self, phone_number: str, message: str) -> None:
        """Simulate sending an SMS to a phone number."""
        if phone_number not in self.inbox:
            self.inbox[phone_number] = []
        self.inbox[phone_number].append(message)
        print(f"[SMS Gateway] Sent to {phone_number}: {message[:50]}...")  # Truncate long logs

    def receive_sms(self, phone_number: str) -> str | None:
        """Simulate receiving the oldest SMS from a phone number."""
        if phone_number in self.inbox and self.inbox[phone_number]:
            return self.inbox[phone_number].pop(0)
        return None