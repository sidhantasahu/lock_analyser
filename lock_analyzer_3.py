import re
import os
import subprocess
import shutil

class LockInfo:
    def __init__(self, name, file, line):
        self.name = name
        self.file = file
        self.line = line
        self.critical_sections = []

class CriticalSection:
    def __init__(self, function_name, start_line, end_line, accessed_vars, accessed_structs, function_calls, nested_locks):
        self.function_name = function_name
        self.start_line = start_line
        self.end_line = end_line
        self.accessed_vars = accessed_vars
        self.accessed_structs = accessed_structs
        self.function_calls = function_calls
        self.nested_locks = nested_locks

def print_file_content(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='iso-8859-1') as file:
            lines = file.readlines()
    
    for i, line in enumerate(lines, 1):
        print(f"{i:4d}: {line.rstrip()}")

def parse_c_file(file_path):
    locks = {}
    current_function = ""
    in_function = False
    function_content = []
    brace_count = 0

    print(f"Parsing file: {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='iso-8859-1') as file:
                lines = file.readlines()
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}")
            return {}

    for i, line in enumerate(lines, 1):
        stripped_line = line.strip()

        # Track function definitions
        if not in_function:
            func_match = re.match(r'(\w+(?:\s+\w+)*)\s+(\w+)\s*\([^)]*\)\s*\{?', stripped_line)
            if func_match:
                current_function = func_match.group(2)
                in_function = True
                function_content = [line]
                brace_count = stripped_line.count('{')
                print(f"Found function: {current_function} at line {i}")
        elif in_function:
            function_content.append(line)
            brace_count += stripped_line.count('{') - stripped_line.count('}')
            if brace_count == 0:
                print(f"Processing function: {current_function}")
                try:
                    process_function(current_function, function_content, file_path, locks, i - len(function_content))
                except Exception as e:
                    print(f"Error processing function {current_function}: {str(e)}")
                    print(f"Function content: {function_content}")
                in_function = False
                function_content = []

    return locks

def process_function(function_name, function_content, file_path, locks, start_line_offset):
    lock_patterns = [
        # Mutex locks
        (r'mutex_lock(_nested|_interruptible|_killable)?\s*\(\s*(&?)([^,\)]+)', 'lock', 'mutex'),
        (r'mutex_unlock\s*\(\s*(&?)([^,\)]+)', 'unlock', 'mutex'),
        
        # Spinlocks
        (r'spin_lock(_nested|_irq|_irqsave|_bh)?\s*\(\s*(&?)([^,\)]+)', 'lock', 'spinlock'),
        (r'spin_unlock(_irq|_irqrestore|_bh)?\s*\(\s*(&?)([^,\)]+)', 'unlock', 'spinlock'),
        
        # RW locks
        (r'read_lock(_irq|_irqsave|_bh)?\s*\(\s*(&?)([^,\)]+)', 'lock', 'rwlock'),
        (r'read_unlock(_irq|_irqrestore|_bh)?\s*\(\s*(&?)([^,\)]+)', 'unlock', 'rwlock'),
        (r'write_lock(_irq|_irqsave|_bh)?\s*\(\s*(&?)([^,\)]+)', 'lock', 'rwlock'),
        (r'write_unlock(_irq|_irqrestore|_bh)?\s*\(\s*(&?)([^,\)]+)', 'unlock', 'rwlock'),
        
        # RCU
        (r'rcu_read_lock\s*\(\s*\)', 'lock', 'rcu'),
        (r'rcu_read_unlock\s*\(\s*\)', 'unlock', 'rcu'),
        (r'srcu_read_lock\s*\(\s*(&?)([^,\)]+)', 'lock', 'srcu'),
        (r'srcu_read_unlock\s*\(\s*(&?)([^,\)]+)', 'unlock', 'srcu'),
        
        # Seqlocks
        (r'write_seqlock(_irq|_irqsave|_bh)?\s*\(\s*(&?)([^,\)]+)', 'lock', 'seqlock'),
        (r'write_sequnlock(_irq|_irqrestore|_bh)?\s*\(\s*(&?)([^,\)]+)', 'unlock', 'seqlock'),
        (r'read_seqbegin\s*\(\s*(&?)([^,\)]+)', 'lock', 'seqlock'),
        (r'read_seqretry\s*\(\s*(&?)([^,\)]+)', 'unlock', 'seqlock'),
        
        # RW Semaphores
        (r'down_read\s*\(\s*(&?)([^,\)]+)', 'lock', 'rwsem'),
        (r'up_read\s*\(\s*(&?)([^,\)]+)', 'unlock', 'rwsem'),
        (r'down_write\s*\(\s*(&?)([^,\)]+)', 'lock', 'rwsem'),
        (r'up_write\s*\(\s*(&?)([^,\)]+)', 'unlock', 'rwsem'),
        
        # Completion
        (r'wait_for_completion(_interruptible|_killable|_timeout)?\s*\(\s*(&?)([^,\)]+)', 'lock', 'completion'),
        (r'complete(_all)?\s*\(\s*(&?)([^,\)]+)', 'unlock', 'completion'),
        
        # Raw spinlocks
        (r'raw_spin_lock(_irq|_irqsave|_bh)?\s*\(\s*(&?)([^,\)]+)', 'lock', 'raw_spinlock'),
        (r'raw_spin_unlock(_irq|_irqrestore|_bh)?\s*\(\s*(&?)([^,\)]+)', 'unlock', 'raw_spinlock'),
        
        # Bit spinlocks
        (r'bit_spin_lock\s*\(\s*([^,]+),\s*([^,\)]+)', 'lock', 'bit_spinlock'),
        (r'bit_spin_unlock\s*\(\s*([^,]+),\s*([^,\)]+)', 'unlock', 'bit_spinlock'),
        
        # RCU sync
        (r'synchronize_rcu\s*\(\s*\)', 'sync', 'rcu'),
        (r'synchronize_srcu\s*\(\s*(&?)([^,\)]+)', 'sync', 'srcu'),
        
        # Atomic operations
        (r'atomic_(inc|dec|add|sub|set|and|or|xor)\s*\(\s*(&?)([^,\)]+)', 'atomic', 'atomic'),
        (r'atomic_(inc|dec|add|sub|set|and|or|xor)_return\s*\(\s*(&?)([^,\)]+)', 'atomic', 'atomic'),
        
        # Memory barriers
        (r'(mb|rmb|wmb|smp_mb|smp_rmb|smp_wmb)\s*\(\s*\)', 'barrier', 'memory_barrier'),
        
        # Percpu operations
        (r'get_cpu\s*\(\s*\)', 'lock', 'percpu'),
        (r'put_cpu\s*\(\s*\)', 'unlock', 'percpu'),
        
        # Local interrupt disabling
        (r'local_irq_disable\s*\(\s*\)', 'lock', 'irq'),
        (r'local_irq_enable\s*\(\s*\)', 'unlock', 'irq'),
        
        # Preemption control
        (r'preempt_disable\s*\(\s*\)', 'lock', 'preemption'),
        (r'preempt_enable\s*\(\s*\)', 'unlock', 'preemption'),
    ]
    
    lock_stack = []
    for i, line in enumerate(function_content):
        for pattern, lock_type, lock_category in lock_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                try:
                    if lock_category in ['rcu', 'memory_barrier', 'percpu', 'irq', 'preemption']:
                        lock_name = lock_category
                    elif lock_category == 'bit_spinlock':
                        lock_name = f"bit_{match.group(1)}_{match.group(2)}"
                    elif lock_category == 'atomic':
                        lock_name = f"atomic_{match.group(3)}"
                    else:
                        amp = match.group(2) if len(match.groups()) > 2 else ''
                        lock_name = match.group(3) if len(match.groups()) > 2 else match.group(2)
                        if amp == '&':
                            lock_name = '&' + lock_name
                    
                    full_lock_name = f"{lock_category}:{lock_name}"
                    
                    if lock_type in ['lock', 'sync', 'atomic', 'barrier']:
                        lock_stack.append((full_lock_name, i))
                        print(f"Found {lock_type} for {full_lock_name} in {function_name} at line {start_line_offset + i + 1}")
                        if full_lock_name not in locks:
                            locks[full_lock_name] = LockInfo(full_lock_name, file_path, start_line_offset + i + 1)
                    elif lock_type == 'unlock':
                        matching_lock = None
                        for j, (stacked_lock, start_line) in enumerate(reversed(lock_stack)):
                            if stacked_lock == full_lock_name:
                                matching_lock = lock_stack.pop(len(lock_stack) - 1 - j)
                                break
                        if matching_lock:
                            start_line = matching_lock[1]
                            end_line = i
                            process_critical_section(function_name, function_content[start_line:end_line+1], 
                                                     file_path, locks, full_lock_name, start_line_offset + start_line + 1, start_line_offset + end_line + 1, lock_stack)
                            print(f"Found matching unlock for {full_lock_name} in {function_name} at line {start_line_offset + i + 1}")
                        else:
                            print(f"Warning: Unmatched unlock for {full_lock_name} in {function_name} at line {start_line_offset + i + 1}")
                except IndexError:
                    print(f"Warning: Failed to process lock in {function_name} at line {start_line_offset + i + 1}: {line.strip()}")
                    print(f"Match groups: {match.groups()}")

    # Handle unclosed locks at the end of the function
    while lock_stack:
        lock_name, start_line = lock_stack.pop()
        end_line = len(function_content) - 1
        process_critical_section(function_name, function_content[start_line:], 
                                 file_path, locks, lock_name, start_line_offset + start_line + 1, start_line_offset + end_line + 1, lock_stack)
        print(f"Warning: Unclosed lock {lock_name} in {function_name} at end of function")

    if not locks:
        print(f"No locks found in function: {function_name}")

def process_critical_section(function_name, content, file_path, locks, lock_name, start_line, end_line, lock_stack):
    accessed_vars = set()
    accessed_structs = set()
    function_calls = set()
    nested_locks = [lock for lock, _ in lock_stack]

    for line in content:
        # Extract variables and struct accesses
        vars = re.findall(r'\b([a-zA-Z_]\w*)\b', line)
        accessed_vars.update(vars)
        
        structs = re.findall(r'(\w+(?:(?:->|\.)\w+)+)', line)
        accessed_structs.update(structs)
        
        # Extract function calls
        func_calls = re.findall(r'(\w+)\s*\(', line)
        function_calls.update(func_calls)

    cs = CriticalSection(function_name, start_line, end_line, accessed_vars, accessed_structs, function_calls, nested_locks)
    locks[lock_name].critical_sections.append(cs)
    print(f"Added critical section for {lock_name} in {function_name} from line {start_line} to {end_line}")
    print(f"  Accessed vars: {', '.join(accessed_vars)}")
    print(f"  Accessed structs: {', '.join(accessed_structs)}")
    print(f"  Function calls: {', '.join(function_calls)}")
    print(f"  Nested locks: {', '.join(nested_locks)}")

import re

def escape_dot_string(s):
    return re.sub(r'([^a-zA-Z0-9_])', lambda m: f'\\{m.group(1)}', s)

def generate_dot_file(locks, output_file):
    with open(output_file, 'w') as f:
        f.write("digraph LockUsage {\n")
        f.write("  rankdir=LR;\n")  # Left to right layout
        f.write("  node [shape=box];\n")
        f.write("  compound=true;\n")
        
        # Group locks by file
        files = {}
        for lock_name, lock_info in locks.items():
            if lock_info.file not in files:
                files[lock_info.file] = []
            files[lock_info.file].append((lock_name, lock_info))
        
        for file, file_locks in files.items():
            safe_file_name = re.sub(r'[^a-zA-Z0-9_]', '_', file)
            f.write(f'  subgraph cluster_{safe_file_name} {{\n')
            f.write(f'    label="{escape_dot_string(file)}";\n')
            
            for lock_name, lock_info in file_locks:
                safe_lock_name = escape_dot_string(lock_name)
                f.write(f'    "{safe_lock_name}" [label="{escape_dot_string(lock_name)}\\n{lock_info.line}"];\n')
                
                for i, cs in enumerate(lock_info.critical_sections):
                    cs_name = f"{safe_lock_name}_cs_{i}"
                    label = f"CS in {escape_dot_string(cs.function_name)}\\n" \
                            f"Lines {cs.start_line}-{cs.end_line}\\n" \
                            f"Vars: {escape_dot_string(', '.join(list(cs.accessed_vars)[:5]))}\\n" \
                            f"Structs: {escape_dot_string(', '.join(list(cs.accessed_structs)[:5]))}\\n" \
                            f"Calls: {escape_dot_string(', '.join(list(cs.function_calls)[:5]))}\\n" \
                            f"Nested: {escape_dot_string(', '.join(list(cs.nested_locks)[:5]))}"
                    f.write(f'    "{cs_name}" [label="{label}"];\n')
                    f.write(f'    "{safe_lock_name}" -> "{cs_name}";\n')
            
            f.write("  }\n")

        f.write("}\n")

    print(f"DOT file generated: {output_file}")
    print("To view the graph:")
    print(f"1. Use an online viewer: visit https://dreampuf.github.io/GraphvizOnline/ and paste the contents of {output_file}")
    print(f"2. Or, if you have Graphviz installed, run: dot -Tsvg {output_file} -o lock_usage.svg")

def main():
    code_directory = "/Users/sidhu/Learn/Tools/Lock_Graph/wireless-next/drivers/net/wireless/ath/ath11k"  # Update this to your actual code directory
    
    print(f"Analyzing code in directory: {code_directory}")
    
    all_locks = {}
    file_count = 0
    processed_file_count = 0

    for root, dirs, files in os.walk(code_directory):
        for file in files:
            if file.endswith('.c'):
                file_count += 1
                file_path = os.path.join(root, file)
                print(f"Processing file {file_count}: {file_path}")
                try:
                    file_locks = parse_c_file(file_path)
                    all_locks.update(file_locks)
                    processed_file_count += 1
                    print(f"Successfully processed {file_path}")
                    print(f"Locks found in this file: {list(file_locks.keys())}")
                except Exception as e:
                    print(f"Error processing file {file_path}: {str(e)}")

    print(f"\nProcessing complete.")
    print(f"Total .c files found: {file_count}")
    print(f"Files successfully processed: {processed_file_count}")
    print(f"Total unique locks found: {len(all_locks)}")

    if all_locks:
        generate_dot_file(all_locks, "lock_usage.dot")
        print("DOT file generated: lock_usage.dot")
        
        dot_path = shutil.which('dot')
        if dot_path:
            subprocess.run([dot_path, "-Tpng", "lock_usage.dot", "-o", "lock_usage.png"])
            print("PNG file generated: lock_usage.png")
        else:
            print("GraphViz 'dot' command not found. Please install GraphViz and ensure it's in your PATH.")
            print("To create the PNG manually, run: dot -Tpng lock_usage.dot -o lock_usage.png")
    else:
        print("No lock information found. Graph not generated.")

if __name__ == "__main__":
    main()
