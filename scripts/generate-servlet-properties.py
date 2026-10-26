#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Generate Java .properties file from localise.yaml for Tomcat servlet localisation.
This script is run during Maven build to enable regional support for Tomcat servlets.
"""

import yaml
import os
import sys

def flatten_dict(d, parent_key='', sep='.'):
    """
    Flatten nested dictionary into dot-notation keys for Java properties format.
    
    Args:
        d: Dictionary to flatten
        parent_key: Prefix for nested keys
        sep: Separator character (default: '.')
    
    Returns:
        Flattened dictionary with dot-notation keys
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def escape_properties_value(value):
    """
    Escape special characters for Java .properties format.
    
    Args:
        value: String value to escape
    
    Returns:
        Escaped string suitable for .properties file
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Escape backslashes first
    value = value.replace('\\', '\\\\')
    # Escape newlines
    value = value.replace('\n', '\\n')
    # Escape equals and colons
    value = value.replace('=', '\\=')
    value = value.replace(':', '\\:')
    # Escape leading spaces
    if value.startswith(' '):
        value = '\\' + value
    
    return value

def generate_properties(yaml_path, output_path, app_version):
    """
    Generate Java .properties file from YAML configuration.
    
    Args:
        yaml_path: Path to localise.yaml file
        output_path: Path to output .properties file
        app_version: Application version to inject
    """
    try:
        # Read YAML file
        with open(yaml_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # Extract tomcat_servlets section
        if 'tomcat_servlets' not in config:
            print("ERROR: 'tomcat_servlets' section not found in localise.yaml", file=sys.stderr)
            sys.exit(1)
        
        servlet_config = config['tomcat_servlets']
        
        # Flatten the nested structure
        flat_config = flatten_dict(servlet_config)
        
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Write .properties file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# Tomcat Servlet Localisation Properties\n")
            f.write("# SPDX-FileCopyrightText: GoCortexIO\n")
            f.write("# SPDX-License-Identifier: AGPL-3.0-or-later\n")
            f.write("#\n")
            f.write("# Auto-generated from localise.yaml - DO NOT EDIT MANUALLY\n")
            f.write(f"# Application Version: {app_version}\n\n")
            
            # Sort keys for consistent output
            for key in sorted(flat_config.keys()):
                value = flat_config[key]
                escaped_value = escape_properties_value(value)
                
                # Replace {version} placeholder with actual version
                if '{version}' in escaped_value:
                    escaped_value = escaped_value.replace('{version}', app_version)
                
                f.write(f"{key}={escaped_value}\n")
        
        print(f"SUCCESS: Generated {output_path} with {len(flat_config)} properties")
        return 0
        
    except FileNotFoundError:
        print(f"ERROR: File not found: {yaml_path}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"ERROR: Failed to parse YAML: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    """Main entry point for the script."""
    if len(sys.argv) != 4:
        print("Usage: generate-servlet-properties.py <yaml_path> <output_path> <app_version>")
        print("Example: generate-servlet-properties.py config/localise.yaml exploit-app/src/main/resources/servlet-locale.properties 1.7.0")
        sys.exit(1)
    
    yaml_path = sys.argv[1]
    output_path = sys.argv[2]
    app_version = sys.argv[3]
    
    generate_properties(yaml_path, output_path, app_version)

if __name__ == '__main__':
    main()
