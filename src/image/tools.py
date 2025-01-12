from PIL import Image
from typing import Tuple, List


def cropimage(
    image: Image.Image, difficulty: int
) -> Tuple[List[Image.Image], Image.Image]:
    width, height = image.size

    upperhalf = image.crop((0, 0, width, height // 2))
    lowerhalf = image.crop((0, height // 2, width, height))

    uppersegments = [
        upperhalf.crop(
            (
                0,
                i * (height // 2) // difficulty,
                width,
                (i + 1) * (height // 2) // difficulty,
            )
        )
        for i in range(difficulty)
    ]
    lowersegments = [
        lowerhalf.crop(
            (
                0,
                i * (height // 2) // difficulty,
                width,
                (i + 1) * (height // 2) // difficulty,
            )
        )
        for i in range(difficulty)
    ]

    return uppersegments, lowersegments[0]


def cropimage_GT3(image: Image.Image) -> Tuple[List[Image.Image], Image.Image]:
    width, height = image.size

    upperhalf = image.crop((0, 0, width, height // 2))
    lowerhalf = image.crop((0, height // 2, width, height))

    uppersegments = [
        upperhalf.crop((0, i * (height // 2) // 3, width, (i + 1) * (height // 2) // 3))
        for i in range(3)
    ]
    lowersegments = [
        lowerhalf.crop((0, i * (height // 2) // 3, width, (i + 1) * (height // 2) // 3))
        for i in range(3)
    ]

    return uppersegments, lowersegments
