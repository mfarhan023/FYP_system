import os
from PIL import Image, ImageDraw

def main():
    icon_dir = os.path.join(os.path.dirname(__file__), 'icons')
    os.makedirs(icon_dir, exist_ok=True)

    sizes = [16, 48, 128]

    for size in sizes:
        # Blank transparent image
        img = Image.new('RGBA', (size, size), color=(0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        W = size
        H = size

        # Scale coordinates (offsetting slightly to fit thick borders within the canvas boundaries)
        padding = max(1, int(size * 0.05))
        w_scale = W - (2 * padding)
        h_scale = H - (2 * padding)

        # Scale function
        def get_pt(x_ratio, y_ratio):
            x = padding + (x_ratio * w_scale)
            y = padding + (y_ratio * h_scale)
            return int(x), int(y)

        # Coordinates for left half
        left_pts = [
            get_pt(0.12, 0.20),
            get_pt(0.30, 0.23),
            get_pt(0.50, 0.20),
            get_pt(0.50, 0.88),
            get_pt(0.35, 0.81),
            get_pt(0.20, 0.70),
            get_pt(0.12, 0.48)
        ]

        # Coordinates for right half
        right_pts = [
            get_pt(0.50, 0.20),
            get_pt(0.70, 0.23),
            get_pt(0.88, 0.20),
            get_pt(0.88, 0.48),
            get_pt(0.80, 0.70),
            get_pt(0.65, 0.81),
            get_pt(0.50, 0.88)
        ]

        # Coordinates for outline
        outline_pts = [
            get_pt(0.12, 0.20),
            get_pt(0.30, 0.23),
            get_pt(0.50, 0.20),
            get_pt(0.70, 0.23),
            get_pt(0.88, 0.20),
            get_pt(0.88, 0.48),
            get_pt(0.80, 0.70),
            get_pt(0.65, 0.81),
            get_pt(0.50, 0.88),
            get_pt(0.35, 0.81),
            get_pt(0.20, 0.70),
            get_pt(0.12, 0.48)
        ]

        # Colors matching the shield logo:
        # Left half is solid royal blue, right half is sky/cyan blue, outline is medium grey/purple
        left_color = (43, 118, 227, 255)      # #2B76E3
        right_color = (89, 195, 255, 255)     # #59C3FF
        border_color = (130, 137, 150, 255)   # Slate/Grey

        # Draw left and right filled regions
        draw.polygon(left_pts, fill=left_color)
        draw.polygon(right_pts, fill=right_color)

        # Draw the thick border using draw.line with round joints
        border_width = max(1, int(size * 0.06))
        draw.line(outline_pts + [outline_pts[0]], fill=border_color, width=border_width, joint="round")

        # Save icon
        icon_path = os.path.join(icon_dir, f'icon{size}.png')
        img.save(icon_path)
        print(f"Generated shield icon: {icon_path}")

if __name__ == '__main__':
    main()
