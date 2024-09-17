### Example Sorting Repository

#### Overview
This repository contains documentation for the steps and commands used for sorting and deduplication of CSV files. The process involves combining files, cleaning, sorting, and removing duplicates.

---

### Steps and Commands

1. **Create Directory and Move Files**
   ```bash
   mkdir learn_sorting
   mv complaince learn_sorting/
   mv waf learn_sorting/
   ```
   - **Purpose**: Organizes files into a dedicated directory.

2. **Combine Files**
   ```bash
   cat complaince waf > combined.txt
   ```
   - **Purpose**: Merges the contents of `complaince` and `waf` into a single file named `combined.txt`.

3. **Sort Combined File**
   ```bash
   sort combined.txt > sorted.txt
   ```
   - **Purpose**: Sorts the lines in `combined.txt` and saves the result to `sorted.txt`.

4. **Convert Tabs to Commas**
   ```bash
   sed 's/\t/,/g' combined.txt > combined_csv.txt
   ```
   - **Purpose**: Replaces tabs with commas in `combined.txt` and saves it as `combined_csv.txt`.

5. **Remove Empty Lines**
   ```bash
   grep -v '^,,*$' combined_csv.txt > cleaned_csv.txt
   ```
   - **Purpose**: Removes lines that are empty or consist only of commas from `combined_csv.txt`, saving the result to `cleaned_csv.txt`.

6. **Filter Valid Rows**
   ```bash
   awk -F',' 'NF == 3' cleaned_csv.txt > cleaned_and_filtered_csv.txt
   ```
   - **Purpose**: Filters rows with exactly three fields (columns) and saves to `cleaned_and_filtered_csv.txt`.

7. **Sort CSV by Columns**
   ```bash
   sort -t, -k1,1 -k2,2 cleaned_and_filtered_csv.txt > sorted_csv.txt
   ```
   - **Purpose**: Sorts `cleaned_and_filtered_csv.txt` by the first and second columns, saving the result to `sorted_csv.txt`.

8. **Remove Duplicate Lines**
   ```bash
   uniq sorted_csv.txt > unique_csv.txt
   ```
   - **Purpose**: Removes duplicate lines from `sorted_csv.txt` and saves the unique lines to `unique_csv.txt`.

9. **Additional Filtering**
   ```bash
   grep -E '^[^,]*(,[^,]*){2}$' combined_csv.txt > cleaned_csv.txt
   ```
   - **Purpose**: Filters rows to ensure they have exactly two comma-separated values.

---

### Notes
- **Commands Used**: These commands are executed in a Unix-like shell environment.
- **Files**: Make sure to adjust file paths if they are different on your system.
- **Output Files**: Each command generates an output file that you can review to ensure the processing is correct.

---

You can save this information in a `README.md` file in your `example_sorting` GitHub repository. Here’s a template you can use for the `README.md`:

```markdown
# Example Sorting

## Overview
This repository documents the steps and commands used for sorting and deduplication of CSV files.

## Steps and Commands
1. **Create Directory and Move Files**
   ```bash
   mkdir learn_sorting
   mv complaince learn_sorting/
   mv waf learn_sorting/
   ```

2. **Combine Files**
   ```bash
   cat complaince waf > combined.txt
   ```

3. **Sort Combined File**
   ```bash
   sort combined.txt > sorted.txt
   ```

4. **Convert Tabs to Commas**
   ```bash
   sed 's/\t/,/g' combined.txt > combined_csv.txt
   ```

5. **Remove Empty Lines**
   ```bash
   grep -v '^,,*$' combined_csv.txt > cleaned_csv.txt
   ```

6. **Filter Valid Rows**
   ```bash
   awk -F',' 'NF == 3' cleaned_csv.txt > cleaned_and_filtered_csv.txt
   ```

7. **Sort CSV by Columns**
   ```bash
   sort -t, -k1,1 -k2,2 cleaned_and_filtered_csv.txt > sorted_csv.txt
   ```

8. **Remove Duplicate Lines**
   ```bash
   uniq sorted_csv.txt > unique_csv.txt
   ```

9. **Additional Filtering**
   ```bash
   grep -E '^[^,]*(,[^,]*){2}$' combined_csv.txt > cleaned_csv.txt
   ```

## Notes
- **Commands Used**: Executed in a Unix-like shell environment.
- **Files**: Adjust file paths if different.
- **Output Files**: Review output files for correctness.

```
