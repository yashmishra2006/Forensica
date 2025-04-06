import os
from mmaction.apis import init_recognizer, inference_recognizer
import mmcv

# ---- Step 1: Paths ----
config_file = 'mmaction2/configs/recognition/slowfast/slowfast_r50_4x16x1_256e_kinetics400_rgb.py'
checkpoint_file = 'checkpoints/slowfast_r50.pth'
video_path = '10.mp4'  # Replace with your actual video file

# ---- Step 2: Load Model ----
model = init_recognizer(config_file, checkpoint_file, device='cuda:0')  # or 'cpu'

# ---- Step 3: Inference ----
print(f"\n🔍 Running action recognition on: {video_path}")
results = inference_recognizer(model, video_path)

# ---- Step 4: Print top-1 result ----
if results:
    top_action, score = results[0]
    print(f"\n🎬 Detected Action: {top_action} ({score:.2f} confidence)\n")
else:
    print("\n❌ No action detected.\n")
