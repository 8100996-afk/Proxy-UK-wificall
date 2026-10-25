from .core import collect_xray_traffic, init_db


def main():
    init_db()
    collect_xray_traffic()


if __name__ == "__main__":
    main()
