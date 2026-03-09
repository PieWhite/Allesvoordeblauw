import os
import glob
import pandas as pd

def merge_v2_features():
    directory = "../Binetflowdata"
    all_files = glob.glob(os.path.join(directory, "*_features_v2.csv"))
    
    if not all_files:
        print("No V2 feature files found. Did you run batch_extract_v2.ps1?")
        return

    print(f"Found {len(all_files)} V2 feature files. Merging...")
    
    df_list = []
    total_botnet = 0
    total_normal = 0

    for file in all_files:
        print(f"Reading {os.path.basename(file)}...")
        try:
            df = pd.read_csv(file)
            df_list.append(df)
            
            # Print quick stats about this file
            if 'is_botnet' in df.columns:
                bots = df['is_botnet'].sum()
                norms = len(df) - bots
                total_botnet += bots
                total_normal += norms
                print(f"  -> Rows: {len(df):,}, Botnets: {bots:,}, Normal: {norms:,}")
        except Exception as e:
            print(f"  -> Error reading {file}: {e}")

    if not df_list:
        print("No data loaded. Exiting.")
        return

    print("\nConcatenating all files...")
    master_df = pd.concat(df_list, ignore_index=True)
    
    print("\n--- MASTER DATASET V2 SUMMARY ---")
    print(f"Total Rows:   {len(master_df):,}")
    print(f"Total Botnets:{total_botnet:,}")
    print(f"Total Normal: {total_normal:,}")
    
    if total_botnet > 0:
        print(f"Global Imbalance Ratio: {total_normal / total_botnet:.2f}")

    out_path = os.path.join(directory, "master_features_v2.csv")
    print(f"\nSaving master dataset to {out_path}...")
    master_df.to_csv(out_path, index=False)
    print("Generation V2 complete!")

if __name__ == "__main__":
    merge_v2_features()
