# DepthStAr

DepthStAr is a symbolic execution tool that is built on top of the angr framework to detect security smells in software, and specifically AACs.
AACs are security smells that are described in:
https://www.springerprofessional.de/en/depthstar-deep-strange-arguments-detection/19316752

In order to run the tool run DepthStAr.sh

In the Configurations directory are the settings of the targeted binaries (targets.json) and the AACs that are required to be detected (edge_cases.json).

# Configuration Files

There are three configuration files, each serving a different purpose.

---

## config.json

This file contains general settings that affect the overall behavior of the tool.

- **recursion_limit**  
  Defines the maximum recursion depth allowed during analysis.  
  *Example usage:*  
  ```json
  {
    "recursion_limit": 5000
  }
  ```  
  The tool applies this limit using `sys.setrecursionlimit()` to prevent excessive recursion depth.

- **function_on_arguments**  
  A dictionary mapping function names to argument manipulations.  
  This allows specific functions to have their arguments modified before being checked for vulnerabilities.  
  *Example usage:*  
  ```json
  {
    "function_on_arguments": {
      "malloc": "replace_with_concrete_value"
    }
  }
  ```  
  When encountering a function listed here, the tool applies the specified transformation.

- **known_functions**  (Not yet supported)
  A list of functions that should be concretely executed instead of being symbolically analyzed.  
  These are typically functions known to cause symbolic execution issues, such as certain libc functions.  
  *Example usage:*  
  ```json
  {
    "known_functions": ["__snprintf_chk", "memcpy"]
  }
  ```  
  The tool hooks these functions with appropriate simprocedures to avoid unnecessary state complexity.

---

## edge_cases.json

This file defines the special cases that are considered AACs and are the scenarios that depthstar is looking to detect.

- **function_name**  
  A list of function names that should be monitored during symbolic execution.  
  *Example usage:*  
  ```json
  {
    "function_name": ["memcpy", "buf_cpy"]
  }
  ```  
  When the tool encounters a call to one of these functions, it inspects the specified argument for vulnerabilities.

- **argument_index**  
  Specifies which argument (zero-indexed) should be checked.  
  *Example:*  
  If `argument_index` is `2`, the tool will inspect the third argument of the function call.  
  ```json
  {
    "argument_index": 2
  }
  ```

- **vulnerable_value**  
  A concrete value that, if found in the monitored argument, may indicate a security issue.  
  *Example usage:*  
  ```json
  {
    "vulnerable_value": 0
  }
  ```  
  If the specified argument of a function call equals this value, the tool triggers an AAC detection.

---

## targets.json

This file specifies the binaries to analyze and defines binary-specific execution rules.

- **file_name**  
  The path to the binaries to be analyzed.  
  If the value ends with an asterisk (`*`), the tool treats it as a directory and analyzes all files within that directory.  
  *Example usage:*  
  ```json
  {
    "file_name": "/mnt/hgfs/vm-mount/DepthStAr/samples/to-test/*"
  }
  ```  
  This ensures that all binaries in the specified folder are included in the analysis.

- **blacklist**  
  A list of functions that should be skipped during symbolic execution.  
  *Example usage:*  
  ```json
  {
    "blacklist": ["sub_406e1c", "sub_406e99"]
  }
  ```  
  These functions will not be used as entry points for exploration, preventing unnecessary state explosion.

- **aggressive**  
  A list of functions that should be analyzed using aggressive execution settings, such as higher state limits and extended timeouts.  
  *Example usage:*  
  ```json
  {
    "aggressive": []
  }
  ```  
  If empty, no functions are explicitly marked for aggressive analysis.

- **whitelist**  
  A list of functions that should be executed concretely rather than symbolically.  
  This is useful for functions involved in program initialization.  
  *Example usage:*  
  ```json
  {
    "whitelist": ["libc_start_main", "__libc_start_main"]
  }
  ```  
  These functions will be run concretely before symbolic execution begins.
