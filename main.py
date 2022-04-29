import uvicorn

#run cmdb search api
if __name__ == "__main__":
    uvicorn.run("cmdb:app", host="0.0.0.0", port = 8000)