import random
import math
import json
import base64
from typing import List, Dict, Tuple
import matplotlib.pyplot as plt


def perlin_noise_1d(x: float, persistence: float = 0.5, octaves: int = 4) -> float:
    total = 0
    frequency = 1
    amplitude = 1
    for _ in range(octaves):
        total += interpolated_noise(x * frequency) * amplitude
        frequency *= 2
        amplitude *= persistence
    return total


def interpolated_noise(x: float) -> float:
    integer_x = int(x)
    fractional_x = x - integer_x
    v1 = smooth_noise(integer_x)
    v2 = smooth_noise(integer_x + 1)
    return cosine_interpolate(v1, v2, fractional_x)


def smooth_noise(x: int) -> float:
    return math.sin(x * 0.1) * random.uniform(-0.5, 0.5)


def cosine_interpolate(a: float, b: float, x: float) -> float:
    ft = x * 3.1415927
    f = (1 - math.cos(ft)) * 0.5
    return a * (1 - f) + b * f



def clamp(x: float, lowerlimit: float, upperlimit: float) -> float:
    return max(lowerlimit, min(x, upperlimit))


class DataGenerator:
    def __init__(self):
        self.dPoints: List[Tuple[int, int]] = []
        self.timestamp: int = 0

    def binomial_coefficient(self, n: int, k: int) -> int:
        if k == 0 or k == n:
            return 1
        return self.binomial_coefficient(n - 1, k - 1) + self.binomial_coefficient(
            n - 1, k
        )

    def random_value(self, min_value: float, max_value: float) -> float:
        return random.uniform(min_value, max_value)

    def bezier_curve(
        self, points: List[Dict[str, float]], path: List[Dict[str, int]], timestamp: int
    ) -> int:
        num_points = len(points) - 1
        resolution = max(1, int(150 / len(self.dPoints) - self.random_value(0, 10)))

        for i in range(resolution + 1):
            t = (i / resolution) ** 2

            x, y = 0, 0
            for j in range(num_points + 1):
                binomial = (
                    self.binomial_coefficient(num_points, j)
                    * (1 - t) ** (num_points - j)
                    * t**j
                )
                x += points[j]["x"] * binomial
                y += points[j]["y"] * binomial

            x += self.random_value(-2, 6)
            y += self.random_value(-1, 7)

            if path:
                last_point = path[-1]
                # ∆x = x[t] - x[t-1]
                dx = x - last_point["x"]
                # ∆y = y[t] - y[t-1]
                dy = y - last_point["y"]

                # ∆t = t[t] - t[t-1]
                dt = timestamp - last_point["timestamp"]

                if dt > 0:
                    vx = dx / dt
                    vy = dy / dt
                    print(f"Velocity: vx = {vx:.2f}, vy = {vy:.2f}")

                distance_to_last_point = math.sqrt(dx**2 + dy**2)
            else:
                distance_to_last_point = 0

            if distance_to_last_point > 0.1 or not path:
                timestamp += int(self.random_value(80, 120))
                path.append(
                    {"timestamp": int(timestamp), "type": 0, "x": int(x), "y": int(y)}
                )

        return timestamp

    def generate_random_points(self, index: int) -> List[Dict[str, float]]:
        start = [700, 200] if index == 0 else self.dPoints[index - 1]
        end = self.dPoints[index]

        midpoint_x = (start[0] + end[0]) / 2
        noise_scale = 0.17
        noise_offset = perlin_noise_1d(index * noise_scale) * 210
        midpoint_y = (start[1] + end[1]) / 2 + self.random_value(0, 210) + noise_offset

        return [
            {"x": start[0], "y": start[1]},
            {"x": midpoint_x, "y": midpoint_y},
            {"x": end[0], "y": end[1]},
        ]

    def generate_motion_data(self) -> List[Dict[str, int]]:
        self.timestamp = int(self.random_value(0, 70))
        motion_curve_data: List[Dict[str, int]] = []

        for i in range(len(self.dPoints)):
            control_points = self.generate_random_points(i)
            self.timestamp = self.bezier_curve(
                control_points, motion_curve_data, self.timestamp
            )

        # print(motion_curve_data)
        return motion_curve_data

    def generate_motion_data_str(self) -> str:
        self.timestamp = int(self.random_value(0, 70))

    def generate_key_data(self) -> str:
        self.timestamp = int(self.random_value(0, 70))
        key_curve_data: List[Dict[str, int]] = []

        for _ in range(int(self.random_value(25, 50))):
            self.timestamp += int(self.random_value(1000, 5010))
            key_curve_data.append(
                {
                    "timestamp": self.timestamp,
                    "type": int(self.random_value(1, 3)),
                    "extra": 0,
                }
            )

        return ";".join(
            f"{p['timestamp']},{p['type']},{p['extra']}" for p in key_curve_data
        )

    def generate_d_points(self) -> List[Tuple[int, int]]:
        self.dPoints = []
        for _ in range(int(self.random_value(3, 6))):
            x, y = int(self.random_value(700, 1320)), int(self.random_value(300, 700))
            self.dPoints.append((x, y))
        return self.dPoints

    def generate(self) -> str:
        self.dPoints = self.generate_d_points()
        motion_data = self.generate_motion_data()
        key_data = self.generate_key_data()

        data = {"mbio": motion_data, "tbio": "", "kbio": key_data}

        data_json = json.dumps(data, separators=(",", ":"))
        return base64.b64encode(data_json.encode("utf-8")).decode("utf-8")


def convert_list_to_str(list_of_dicts):
    """Converts a list of dictionaries to a CSV-formatted string.

    Args:
      list_of_dicts: A list of dictionaries, where each dictionary
                     should contain 'timestamp', 'type', 'x', and 'y' keys.

    Returns:
      A CSV string representation of the data. Returns an error message if the input is invalid.
    """
    if not isinstance(list_of_dicts, list):
        return "Error: Input must be a list of dictionaries."

    required_keys = {"timestamp", "type", "x", "y"}
    for item in list_of_dicts:
        if not isinstance(item, dict) or not required_keys.issubset(item.keys()):
            return "Error: Dictionaries must contain 'timestamp', 'type', 'x', and 'y' keys."

    movement: str = ""
    for item in list_of_dicts:
        movement += f"{item['timestamp']},{item['type']},{item['x']},{item['y']};"
    return movement


if __name__ == "__main__":
    generator = DataGenerator()
    generator.generate_d_points()
    motion_data = generator.generate_motion_data()
    print(motion_data)

    print(convert_list_to_str(motion_data))

    plot = plt.plot([i["x"] for i in motion_data], [i["y"] for i in motion_data])
    plt.show()