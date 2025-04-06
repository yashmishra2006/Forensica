import cv2
import json
import os
from inference_sdk import InferenceHTTPClient

CLIENT = InferenceHTTPClient(
    api_url="https://detect.roboflow.com",
    api_key="hY9qOmC03Dpg4JNVNeOp"
)

MODEL_ID = "weapon-jmeyk/1"

video_path = "data/vid3.mp4"
cap = cv2.VideoCapture(video_path)

frame_skip = 25  # Process every 5th frame
frame_id = 0
output = []

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    if frame_id % frame_skip == 0:
        frame_name = f"frame_{frame_id}.jpg"
        cv2.imwrite(frame_name, frame)

        try:
            result = CLIENT.infer(frame_name, model_id=MODEL_ID)

            if result["predictions"]:
                detected_tags = list(set([pred["class"] for pred in result["predictions"]]))
                summary = f"Detected potential threats: {', '.join(detected_tags)} in frame {frame_id}."

                frame_entry = {
                    "path": f"frames\\{frame_name}",
                    "type": "image",
                    "content": summary,
                    "tags": detected_tags,
                    "sensitive_info": {
                        "flags": [],
                        "detected_entities": {
                            "emails": [],
                            "phones": [],
                            "urls": [],
                            "base64_strings": False
                        }
                    }
                }
                output.append(frame_entry)

        except Exception as e:
            print(f"Error in frame {frame_id}: {e}")

        os.remove(frame_name)

    frame_id += 1

cap.release()

with open("formatted_threat_detections.json", "w") as f:
    json.dump(output, f, indent=4)

print("✅ Detections saved in formatted JSON.")