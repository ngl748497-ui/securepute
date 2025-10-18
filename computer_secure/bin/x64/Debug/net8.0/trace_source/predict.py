import json
import numpy as np
import os
import re
import tensorflow as tf
from typing import Optional, List, Dict
from tensorflow.keras.models import load_model
from tensorflow.keras.layers import BatchNormalization
import pandas as pd

JSON_TRACE_PATH = 'trace_result.json' 
MODEL_PATH = 'FINAL9.h5' 
FEATURE_LIST_PATH = 'feature_list.txt' 
MALWARE_THRESHOLD = 0.5
int_to_label_map = {0: 'adware', 1: 'backdoor', 2: 'benign', 3: 'downloader', 4: 'spyware', 5: 'trojan', 6: 'virus', 7: 'worm'} 
BENIGN_LABEL_INDEX = 2 


def generalize_feature(feature_name: str) -> str:
    parts = feature_name.split('_', 1)
    if len(parts) < 2: return feature_name
    syscall, param = parts
    
    if 'HKEY_' in param:
        match = re.search(r'(HKEY_[A-Z_]+)', param)
        reg_root = match.group(0) if match else "REGISTRY_OTHER"
        return f"{syscall}_{reg_root}"
        
    param_lower = param.lower().replace('\\\\', '\\')
    if 'appdata\\local\\temp' in param_lower: return f"{syscall}_DIR_APPDATA_TEMP"
    if 'windows\\system32' in param_lower: return f"{syscall}_DIR_WIN_SYSTEM32"
    if 'programdata' in param_lower: return f"{syscall}_DIR_PROGRAMDATA"
    
    if ('.' in param and len(param) < 100) and ('\\' in param or '/' in param):
        _, extension = os.path.splitext(param)
        if extension and len(extension) <= 5: 
            return f"{syscall}_EXT_{extension.upper().replace('.', '')}"
    
    if len(param) > 100:
        return f"{syscall}_PARAM_LONG"
    
    return feature_name

def create_feature_vector_for_group(traces_list: List[Dict], feature_map: Dict[str, int]) -> Optional[np.ndarray]:

    num_generalized_features = len(feature_map)
    vectorize = np.zeros(num_generalized_features, dtype=float)
    
    for trace in traces_list: 
        syscall_name = trace.get('syscallName')
        affected_object = trace.get('affectedObject')
        called_time = trace.get('calledTime', 0) 

        if not syscall_name or not affected_object: continue

        combined_feature = f"{syscall_name}_{affected_object}"
        generalized_feature = generalize_feature(combined_feature)

        if generalized_feature in feature_map:
            index = feature_map[generalized_feature]
            vectorize[index] += called_time
            
    return vectorize


def group_traces_by_process(all_traces: List[Dict]) -> Dict[str, List[Dict]]:
    grouped_data = {}
    for trace in all_traces:
        process_name = trace.get('processName', 'UNKNOWN_PROCESS') 
        key = process_name
        
        if key not in grouped_data:
            grouped_data[key] = []
        
        grouped_data[key].append(trace)
    return grouped_data


def main_prediction_pipeline():
    
    try:
        with open(FEATURE_LIST_PATH, 'r', encoding='utf-8') as f:
            feature_list = [line.strip() for line in f if line.strip()]
            feature_map = {feature: i for i, feature in enumerate(feature_list)}
            
        with open(JSON_TRACE_PATH, encoding='utf-8') as file:
            all_traces = json.load(file)

        model = load_model(
            MODEL_PATH,
            custom_objects={'BatchNormalization': tf.keras.layers.BatchNormalization}
        )
        print(f"tải xong mô hình.")

    except FileNotFoundError as e:
        print(f"thiếu: {e.filename}")
        return
    except Exception as e:
        print(f"lỗi model: {e}")
        return

    grouped_processes = group_traces_by_process(all_traces)
    final_results = []
    
    print(f"\nBắt đầu dự đoán cho tổng cộng {len(grouped_processes)} nhóm tiến trình...")
    
    for process_key, traces_list in grouped_processes.items():
        
        if len(traces_list) < 5: continue
        
        process_vector = create_feature_vector_for_group(traces_list, feature_map)
        
        if process_vector is not None:
            input_vector = process_vector.reshape(1, -1).astype(np.float32)
            
            probabilities = model.predict(input_vector, verbose=0)
            
            predicted_index = np.argmax(probabilities, axis=1)[0]
            confidence = probabilities[0][predicted_index]
            
            if predicted_index != BENIGN_LABEL_INDEX and confidence < MALWARE_THRESHOLD:
                final_label = f"benign"
            else:
                final_label = int_to_label_map.get(predicted_index)

            final_results.append({
                'process': process_key,
                'prediction': final_label,
                'confidence': f"{confidence:.4f}",
                'trace_count': len(traces_list)
            })
            with open("prediction_output.json", "w") as f:
                json.dump(final_results, f, indent=4)
            
    if final_results:
        df_results = pd.DataFrame(final_results)
        df_results = df_results.sort_values(by='trace_count', ascending=False) 
        
        print("\nthreshold 0.5")
        print(df_results.to_string(index=False))
        print(f"\nhoàn thành dự đoán cho {len(final_results)} nhóm tiến trình có hoạt động.")
    else:
        print("không tìm thấy tiến trình nào có hoạt động đáng kể để dự đoán.")


if __name__ == '__main__':
    main_prediction_pipeline()