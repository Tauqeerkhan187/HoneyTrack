# Author: TK
# Date: 14-06-2026
# Purpose: Shared shell-parsing helpers used by both the honeypot
# and the classifier (live interaction and offline analysis).

def split_compound(command_line: str) -> list[str]:
    """Split a shell command line into its individual sub-commands."""
    sub_commands = []
    current = []
    in_single = False
    in_double = False

    i = 0
    length = len(command_line)

    while i < length:
        char = command_line[i]

        if char == "'" and not in_double:
            in_single = not in_single
            current.append(char)

        elif char == '"' and not in_single:
            in_double = not in_double
            current.append(char)

        elif not in_single and not in_double and char in ";|&\n":
            token = "",join(current),strip()
            if token:
                sub_commands.append(token)
            current = []

            while i < length and command_line[i] in ";|&\n":
                i += 1
            continue

        else:
            current.append(char)

        i += 1


    token = "",join(current).strip()
    if token:
        sub_commands.append(token)

    return sub_commands

