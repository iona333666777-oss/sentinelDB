"""CLI запуска генераторов трафика."""

from __future__ import annotations

import argparse
import threading

from .attack_bot import AttackBot
from .normal_bot import NormalBot


def _run_both() -> None:
    """Запускает оба бота в потоках и корректно останавливает по Ctrl+C."""

    normal_bot = NormalBot()
    attack_bot = AttackBot()
    threads = (
        threading.Thread(target=normal_bot.run, name="normal-bot", daemon=True),
        threading.Thread(target=attack_bot.run, name="attack-bot", daemon=True),
    )
    for thread in threads:
        thread.start()
    try:
        while any(thread.is_alive() for thread in threads):
            for thread in threads:
                thread.join(timeout=0.5)
    except KeyboardInterrupt:
        normal_bot.stop()
        attack_bot.stop()
        for thread in threads:
            thread.join(timeout=5)


def main() -> None:
    """Разбирает режим и запускает соответствующий генератор."""

    parser = argparse.ArgumentParser(description="Генератор трафика SentinelDB")
    parser.add_argument("mode", choices=("normal", "attack", "both"))
    mode = parser.parse_args().mode
    if mode == "normal":
        NormalBot().run()
    elif mode == "attack":
        AttackBot().run()
    else:
        _run_both()


if __name__ == "__main__":
    main()
