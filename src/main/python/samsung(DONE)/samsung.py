import cv2
import numpy as np

img = cv2.imread('samsung.png')

b, g, r = cv2.split(img)

bit_plane = 0

green_bit_plane = (g >> bit_plane) & 1
green_bit_plane *= 255

cv2.imwrite(f'green_bit_plane_{bit_plane}.png', green_bit_plane)
cv2.imshow('Green Bit Plane', green_bit_plane)
cv2.waitKey(0)
cv2.destroyAllWindows()