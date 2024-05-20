class Receiver():
    def __init__(self):
        self.counter=1
    def get_signal(self):
        print("signal received")
        self.counter=self.counter+1