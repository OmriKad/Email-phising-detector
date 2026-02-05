"""Entry point for running the FastAPI application."""
import uvicorn


def main():
    """Run the FastAPI application with uvicorn."""
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()
