from fastapi import FastAPI

app = FastAPI()

value = 0

@app.get("/1")
def value():
    return {"red": "150", "green": "150", "blue": "150"}

@app.get("/2")
def value():
    return {"red": "0", "green": "0", "blue": "0"}

