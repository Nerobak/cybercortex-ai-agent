import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from tools.scope_guard import enforce_scope

print(enforce_scope("https://example.com"))
print(enforce_scope("https://google.com"))
