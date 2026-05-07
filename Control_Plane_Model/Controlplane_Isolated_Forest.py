import pandas as pd
import numpy as np
from scapy.all import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score, classification_report, \
    confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
import warnings
import time
import os
import random
from collections import defaultdict

warnings.filterwarnings('ignore')

# ========== 可调参数宏定义区域 ==========
# 特征提取参数
MAX_PAYLOAD_LENGTH = 512
ENTROPY_WINDOW = 32
SPECIAL_CHARS = ["'", "\"", ";", "--", "/*", "*/", "=", "%", "|", "&"]
BINARY_PATTERNS = [b"\x90" * 4, b"\x00" * 8, b"\xff" * 4]

# 模型训练参数
RF_N_ESTIMATORS = 50
RF_MAX_DEPTH = 15
RF_RANDOM_STATE = 42

# 检测阈值
ANOMALY_THRESHOLD = 0.7

# 数据分割参数
TRAIN_TEST_SPLIT_RATIO = 0.7  # 70%用于训练，30%用于测试
ANOMALY_RANGE = (1000, 1500)  # payload异常包范围，用于221 256行打标签
# ANOMALY_RANGE = (1900, 2950) #dataplane异常范围 2000-3000

# payload dataset path
NORMAL_PCAP_PATH = "../dataset_generation/payload/normal.pcap"  # 正常流量文件
SQL_INJECTION_PCAP_PATH = "../dataset_generation/payload/sql_injection_attack_dataset.pcap"  # SQL注入攻击文件
BUFFER_OVERFLOW_PCAP_PATH = "../dataset_generation/payload/buffer_overflow_dataset.pcap"  # 缓冲区溢出文件
S7COMM_ATTACK_PCAP_PATH = "../dataset_generation/payload/s7comm_attack_dataset.pcap"  # S7comm攻击文件

#dataplane test
# NORMAL_PCAP_PATH = "../dataset_generation/dataplane/normal_dataplane.pcap"
# SQL_INJECTION_PCAP_PATH = "../dataset_generation/dataplane/Siemens_synflood.pcap"
# BUFFER_OVERFLOW_PCAP_PATH = "../dataset_generation/dataplane/Siemens_tcpflood.pcap"
# S7COMM_ATTACK_PCAP_PATH = "../dataset_generation/dataplane/Siemens_icmpflood.pcap"

# ========== 参数定义结束 ==========

class OptimizedPacketAnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = None
        self.training_time = 0
        self.detection_time = 0
        self.is_trained = False

    def calculate_entropy(self, data):
        """计算字节熵值"""
        if len(data) == 0:
            return 0
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]
        return -np.sum(probabilities * np.log2(probabilities))

    def extract_sql_injection_features(self, payload):
        """提取SQL注入相关特征"""
        if not payload:
            return [0] * 5
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
        except:
            return [0] * 5

        features = []
        special_char_count = sum(payload_str.count(char) for char in SPECIAL_CHARS)
        features.append(special_char_count / len(payload_str) if payload_str else 0)

        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'exec', 'xp_']
        keyword_count = sum(payload_str.count(keyword) for keyword in sql_keywords)
        features.append(keyword_count)

        comment_patterns = ['--', '/*', '*/', '#']
        comment_count = sum(payload_str.count(pattern) for pattern in comment_patterns)
        features.append(comment_count)

        equals_quotes = payload_str.count('=') + payload_str.count('"') + payload_str.count("'")
        features.append(equals_quotes / len(payload_str) if payload_str else 0)

        encoding_patterns = ['%25', '%27', '%20', '0x']
        encoding_count = sum(payload_str.count(pattern) for pattern in encoding_patterns)
        features.append(encoding_count)

        return features

    def extract_buffer_overflow_features(self, payload):
        """提取缓冲区溢出相关特征"""
        if not payload:
            return [0] * 5

        features = []
        payload_bytes = bytes(payload)

        nop_count = payload_bytes.count(b'\x90')
        features.append(nop_count / len(payload_bytes) if payload_bytes else 0)

        null_count = payload_bytes.count(b'\x00')
        features.append(null_count / len(payload_bytes) if payload_bytes else 0)

        printable_chars = sum(1 for byte in payload_bytes if 32 <= byte <= 126)
        features.append(printable_chars / len(payload_bytes) if payload_bytes else 0)

        entropy = self.calculate_entropy(payload_bytes)
        features.append(entropy / 8.0)

        max_repeat = 0
        for pattern in BINARY_PATTERNS:
            count = payload_bytes.count(pattern)
            max_repeat = max(max_repeat, count)
        features.append(max_repeat)

        return features

    def extract_s7comm_features(self, payload):
        """提取S7comm协议攻击特征"""
        if not payload:
            return [0] * 5

        features = []
        payload_bytes = bytes(payload)

        s7comm_header = payload_bytes.startswith(b'\x32') if len(payload_bytes) > 0 else False
        features.append(1 if s7comm_header else 0)

        function_code_anomaly = 0
        if len(payload_bytes) > 1:
            function_code = payload_bytes[1]
            if function_code not in [0x04, 0x05, 0x1a, 0x1c, 0x1d, 0x1e]:
                function_code_anomaly = 1
        features.append(function_code_anomaly)

        length_anomaly = 0
        if len(payload_bytes) > 3:
            declared_length = int.from_bytes(payload_bytes[2:4], byteorder='big')
            if declared_length != len(payload_bytes) - 4:
                length_anomaly = 1
        features.append(length_anomaly)

        reserved_field_used = 0
        if len(payload_bytes) > 5:
            if payload_bytes[4] != 0x00:
                reserved_field_used = 1
        features.append(reserved_field_used)

        pdu_anomaly = 0
        if len(payload_bytes) > 10:
            pdu_type = payload_bytes[10]
            if pdu_type not in [0x01, 0x02, 0x03, 0x04, 0x05]:
                pdu_anomaly = 1
        features.append(pdu_anomaly)

        return features

    def extract_general_features(self, payload):
        """提取通用网络特征"""
        if not payload:
            return [0] * 5

        payload_bytes = bytes(payload)
        features = []

        features.append(len(payload_bytes))
        features.append(np.mean(list(payload_bytes)) if payload_bytes else 0)
        features.append(np.std(list(payload_bytes)) if len(payload_bytes) > 1 else 0)

        window_entropies = []
        for i in range(0, len(payload_bytes) - ENTROPY_WINDOW + 1, ENTROPY_WINDOW):
            window = payload_bytes[i:i + ENTROPY_WINDOW]
            window_entropies.append(self.calculate_entropy(window))
        features.append(np.mean(window_entropies) if window_entropies else 0)

        high_bytes = sum(1 for byte in payload_bytes if byte > 127)
        features.append(high_bytes / len(payload_bytes) if payload_bytes else 0)

        return features

    def extract_features(self, payload):
        """提取所有特征"""
        features = []
        features.extend(self.extract_general_features(payload))
        features.extend(self.extract_sql_injection_features(payload))
        features.extend(self.extract_buffer_overflow_features(payload))
        features.extend(self.extract_s7comm_features(payload))
        return features

    def load_pcap_data(self, file_path, label, anomaly_range=None, max_packets=3000):
        """从PCAP文件加载数据"""
        if not os.path.exists(file_path):
            print(f"警告: 文件 {file_path} 不存在")
            return [], [], []

        try:
            packets = rdpcap(file_path)
        except Exception as e:
            print(f"读取PCAP文件 {file_path} 时出错: {e}")
            return [], [], []

        X = []
        y = []
        packet_indices = []

        for i, packet in enumerate(packets):
            if i >= max_packets:
                break

            payload = None
            if packet.haslayer('TCP'):
                payload = bytes(packet['TCP'].payload)

            if payload and len(payload) > 0:
                features = self.extract_features(payload)
                X.append(features)

                if anomaly_range and anomaly_range[0] <= i <= anomaly_range[1]:
                    y.append(1)  # 异常
                else:
                    y.append(label)  # 正常

                packet_indices.append(i)

        print(f"从 {file_path} 加载了 {len(X)} 个数据包，其中异常包: {sum(y)}")
        return X, y, packet_indices

    def create_dataset(self):
        """从所有PCAP文件创建数据集"""
        print("正在从PCAP文件创建数据集...")

        X_all = []
        y_all = []

        # 加载正常流量
        if os.path.exists(NORMAL_PCAP_PATH):
            X_normal, y_normal, _ = self.load_pcap_data(NORMAL_PCAP_PATH, 0, None, 2000)
            X_all.extend(X_normal)
            y_all.extend(y_normal)
            print(f"正常流量: {len(X_normal)} 个包")
        else:
            print("未找到正常流量文件")

        # 加载攻击流量
        attack_files = [
            (SQL_INJECTION_PCAP_PATH, "SQL注入"),
            (BUFFER_OVERFLOW_PCAP_PATH, "缓冲区溢出"),
            (S7COMM_ATTACK_PCAP_PATH, "S7comm攻击")
        ]

        for file_path, attack_name in attack_files:
            if os.path.exists(file_path):
                X_attack, y_attack, _ = self.load_pcap_data(file_path, 0, ANOMALY_RANGE, 3000)
                X_all.extend(X_attack)
                y_all.extend(y_attack)
                print(f"{attack_name}: {len(X_attack)} 个包")
            else:
                print(f"未找到 {attack_name} 文件: {file_path}")

        if len(X_all) == 0:
            print("错误: 没有加载到任何数据")
            return None, None, None, None

        # 转换为numpy数组
        X_all = np.array(X_all)
        y_all = np.array(y_all)

        # 随机分割训练集和测试集
        X_train, X_test, y_train, y_test = train_test_split(
            X_all, y_all,
            test_size=1 - TRAIN_TEST_SPLIT_RATIO,
            random_state=RF_RANDOM_STATE,
            stratify=y_all
        )

        print(f"\n数据集统计:")
        print(f"总样本数: {len(X_all)}")
        print(f"训练集: {len(X_train)} 个样本 (正常: {np.sum(y_train == 0)}, 异常: {np.sum(y_train == 1)})")
        print(f"测试集: {len(X_test)} 个样本 (正常: {np.sum(y_test == 0)}, 异常: {np.sum(y_test == 1)})")

        return X_train, X_test, y_train, y_test

    def train_and_evaluate(self):
        """训练模型并在测试集上评估"""
        print("\n开始训练异常检测模型...")

        start_time = time.time()

        # 创建数据集
        dataset = self.create_dataset()
        if dataset is None:
            return False

        X_train, X_test, y_train, y_test = dataset

        # 特征标准化
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # 训练随机森林模型
        self.model = RandomForestClassifier(
            n_estimators=RF_N_ESTIMATORS,
            max_depth=RF_MAX_DEPTH,
            random_state=RF_RANDOM_STATE
        )

        self.model.fit(X_train_scaled, y_train)

        # 在测试集上评估
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]

        self.training_time = time.time() - start_time

        # 计算所有评估指标
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        # 计算混淆矩阵
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        # 计算其他指标
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0

        print("\n" + "=" * 60)
        print("模型评估结果")
        print("=" * 60)
        print(f"训练时间: {self.training_time:.2f}秒")

        print(f"\n主要指标:")
        print(f"准确率 (Accuracy): {accuracy:.4f}")
        print(f"精确率 (Precision): {precision:.4f}")
        print(f"召回率 (Recall): {recall:.4f}")
        print(f"F1分数: {f1:.4f}")

        print(f"\n其他指标:")
        print(f"特异度 (Specificity): {specificity:.4f}")
        print(f"假阳性率 (FPR): {false_positive_rate:.4f}")
        print(f"假阴性率 (FNR): {false_negative_rate:.4f}")

        print(f"\n混淆矩阵:")
        print(f"真阴性 (TN): {tn}")
        print(f"假阳性 (FP): {fp}")
        print(f"假阴性 (FN): {fn}")
        print(f"真阳性 (TP): {tp}")

        print(f"\n详细分类报告:")
        print(classification_report(y_test, y_pred, target_names=['正常', '异常'], zero_division=0))

        self.is_trained = True
        return True

    def analyze_pcap_file(self, pcap_file, expected_anomaly_range=None):
        """分析单个PCAP文件并检测异常"""
        if not self.is_trained:
            print("错误: 模型尚未训练，无法进行分析")
            return []

        print(f"\n分析PCAP文件: {pcap_file}")

        if not os.path.exists(pcap_file):
            print(f"错误: 文件 {pcap_file} 不存在")
            return []

        start_time = time.time()

        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"读取PCAP文件 {pcap_file} 时出错: {e}")
            return []

        anomalies = []
        all_predictions = []

        for i, packet in enumerate(packets):
            if i >= 3000:
                break

            payload = None
            if packet.haslayer('TCP'):
                payload = bytes(packet['TCP'].payload)

            if payload and len(payload) > 0:
                features = self.extract_features(payload)
                features_scaled = self.scaler.transform([features])

                prediction = self.model.predict(features_scaled)[0]
                probability = self.model.predict_proba(features_scaled)[0][1]

                actual_anomaly = 0
                if expected_anomaly_range:
                    actual_anomaly = 1 if expected_anomaly_range[0] <= i <= expected_anomaly_range[1] else 0

                all_predictions.append({
                    'packet_index': i,
                    'prediction': prediction,
                    'probability': probability,
                    'actual_anomaly': actual_anomaly
                })

                if prediction == 1 or probability > ANOMALY_THRESHOLD:
                    attack_type = self.classify_attack_type(features)
                    anomalies.append({
                        'packet_index': i,
                        'prediction': prediction,
                        'probability': probability,
                        'actual_anomaly': actual_anomaly,
                        'attack_type': attack_type
                    })

        self.detection_time = time.time() - start_time

        # 计算检测性能
        if expected_anomaly_range and all_predictions:
            y_true = [p['actual_anomaly'] for p in all_predictions]
            y_pred = [p['prediction'] for p in all_predictions]

            accuracy = accuracy_score(y_true, y_pred)
            precision = precision_score(y_true, y_pred, zero_division=0)
            recall = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)

            print(f"\n检测性能:")
            print(f"准确率: {accuracy:.4f}")
            print(f"精确率: {precision:.4f}")
            print(f"召回率: {recall:.4f}")
            print(f"F1分数: {f1:.4f}")
            print(f"检测时间: {self.detection_time:.2f}秒")
            print(f"检测到的异常包数量: {len(anomalies)}")

        return anomalies

    def classify_attack_type(self, features):
        """根据特征分类攻击类型"""
        sql_features = features[5:10]
        buffer_features = features[10:15]
        s7comm_features = features[15:20]

        sql_score = sum(sql_features)
        buffer_score = sum(buffer_features)
        s7comm_score = sum(s7comm_features)

        scores = {
            'SQL注入': sql_score,
            '缓冲区溢出': buffer_score,
            'S7comm攻击': s7comm_score
        }

        return max(scores.items(), key=lambda x: x[1])[0]

    def evaluate_on_all_attack_files(self):
        """在所有攻击PCAP文件上评估模型性能"""
        if not self.is_trained:
            print("错误: 模型尚未训练，无法进行评估")
            return

        print("\n" + "=" * 60)
        print("在所有攻击文件上的性能评估")
        print("=" * 60)

        attack_files = [
            (SQL_INJECTION_PCAP_PATH, ANOMALY_RANGE, "SQL注入攻击"),
            (BUFFER_OVERFLOW_PCAP_PATH, ANOMALY_RANGE, "缓冲区溢出攻击"),
            (S7COMM_ATTACK_PCAP_PATH, ANOMALY_RANGE, "S7comm协议攻击")
        ]
2
        total_accuracy = 0
        total_precision = 0
        total_recall = 0
        total_f1 = 0
        file_count = 0

        for file_path, anomaly_range, description in attack_files:
            if os.path.exists(file_path):
                print(f"\n分析: {description}")
                anomalies = self.analyze_pcap_file(file_path, anomaly_range)

                # 计算指标
                if anomalies:
                    y_true = [a['actual_anomaly'] for a in anomalies]
                    y_pred = [a['prediction'] for a in anomalies]

                    accuracy = accuracy_score(y_true, y_pred)
                    precision = precision_score(y_true, y_pred, zero_division=0)
                    recall = recall_score(y_true, y_pred, zero_division=0)
                    f1 = f1_score(y_true, y_pred, zero_division=0)

                    total_accuracy += accuracy
                    total_precision += precision
                    total_recall += recall
                    total_f1 += f1
                    file_count += 1

                    print(f"检测到的异常包示例 (前5个):")
                    for anomaly in anomalies[:5]:
                        print(f"  包序号: {anomaly['packet_index']}, "
                              f"攻击类型: {anomaly['attack_type']}, "
                              f"概率: {anomaly['probability']:.3f}")

        if file_count > 0:
            print(f"\n平均性能指标:")
            print(f"平均准确率: {total_accuracy / file_count:.4f}")
            print(f"平均精确率: {total_precision / file_count:.4f}")
            print(f"平均召回率: {total_recall / file_count:.4f}")
            print(f"平均F1分数: {total_f1 / file_count:.4f}")


def main():
    # 设置随机种子以确保结果可重现
    random.seed(RF_RANDOM_STATE)
    np.random.seed(RF_RANDOM_STATE)

    # 初始化检测器
    detector = OptimizedPacketAnomalyDetector()

    # 训练和评估模型
    success = detector.train_and_evaluate()

    if not success:
        print("训练失败，无法继续后续分析")
        return

    # 在所有攻击PCAP文件上评估模型
    detector.evaluate_on_all_attack_files()

    print(f"\n最终统计:")
    print(f"训练时间: {detector.training_time:.2f}秒")
    print(f"平均检测时间: {detector.detection_time:.2f}秒")


if __name__ == "__main__":
    main()