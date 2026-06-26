import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

from planner import create_plan

goal = """
Perform a security assessment of
https://nerminzlatanovic.com
"""

plan = create_plan(goal)

print(plan)
