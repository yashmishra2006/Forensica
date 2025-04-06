import torch
from torchvision import models, transforms
from PIL import Image
import json

# Load the pre-trained model
model = models.resnet18(pretrained=True)
model.eval()  # Set to evaluation mode

# Image transforms for ResNet
transform = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),  # Convert to tensor
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],  # ResNet trained on ImageNet
        std=[0.229, 0.224, 0.225]
    )
])

# Load ImageNet class labels
def load_labels():
    from urllib.request import urlopen
    LABELS_URL = "https://raw.githubusercontent.com/pytorch/hub/master/imagenet_classes.txt"
    return [line.strip() for line in urlopen(LABELS_URL)]

imagenet_labels = load_labels()

def classify_image(image_path):
    image = Image.open(image_path).convert("RGB")
    img_t = transform(image)
    batch_t = torch.unsqueeze(img_t, 0)

    with torch.no_grad():
        out = model(batch_t)

    _, index = torch.max(out, 1)
    label = imagenet_labels[index[0]]
    print(f"[✓] Classified as: {label}")
    return label

# Example usage
classify_image("image.png")
