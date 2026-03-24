from __future__ import annotations

import ida_kernwin


def _format_row(index: int, row: dict) -> str:
    return (
        f"[{index}] "
        f"local={hex(int(row['local_address']))} "
        f"name='{row['local_name']}' "
        f"score={float(row['score']):.6f} "
        f"match={hex(int(row['match_address']))} "
        f"match_name='{row['match_name']}' "
        f"corpus='{row['corpus']}' "
        f"sha256={row['sha256']}"
    )


def show_results(
    title: str,
    rows: list[dict],
    *,
    apply_one,
    apply_many,
    jump_local,
) -> None:
    if not rows:
        ida_kernwin.msg(f"[*] {title}: no results\n")
        return

    ida_kernwin.msg(f"[*] {title}: {len(rows)} result(s)\n")
    for index, row in enumerate(rows, start=1):
        ida_kernwin.msg(_format_row(index, row) + "\n")

    choice = ida_kernwin.ask_long(
        0,
        f"{title}: enter a result number to act on, -1 to apply all, or 0 to cancel. See the Output window for details.",
    )
    if choice is None or choice == 0:
        return
    if choice == -1:
        apply_many(rows)
        return
    if choice < 1 or choice > len(rows):
        raise RuntimeError(f"invalid result selection: {choice}")

    row = rows[choice - 1]
    action = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_YES,
        "Yes: jump to local function/item\nNo: apply the selected match name\nCancel: abort",
    )
    if action == ida_kernwin.ASKBTN_CANCEL:
        return
    if action == ida_kernwin.ASKBTN_YES:
        jump_local(row)
        return
    apply_one(row)
