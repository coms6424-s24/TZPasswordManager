#!/bin/bash

echo "Applying changes to the application"

# Define the target directory relative to the script location
TARGET_DIR="../optee_qemu/optee_examples/password_manager"

# Check if the target directory exists, create it if it doesn't
if [ ! -d "$TARGET_DIR" ]; then
    echo "Creating directory: $TARGET_DIR"
    mkdir -p "$TARGET_DIR"
fi
echo "Cleaning target directory: $TARGET_DIR"
rm -rf "$TARGET_DIR"/*

# Copy all files and folders from ./app/ to the target directory, overwriting existing files
echo "Copying files to $TARGET_DIR"
cp -r ./app/* "$TARGET_DIR/"

echo "Changes applied. Please build and run the project."
exit 0
                                                                             
~                                                   
