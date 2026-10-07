import argparse
from pathlib import Path
from waitress import serve
from . import create_app


def main():
    parser = argparse.ArgumentParser(description="EvidenceDesk: local authentication triage")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", type=Path, default=Path("instance"))
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    print(f"EvidenceDesk: http://127.0.0.1:{args.port} (single-user local workspace)", flush=True)
    serve(create_app(args.data_dir), host="127.0.0.1", port=args.port, threads=1)


if __name__ == "__main__":
    main()
