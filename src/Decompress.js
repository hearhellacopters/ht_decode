// @ts-check

/**
 * huffRLE
 * 
 * @param {Buffer} nodes 
 * @param {Buffer} in_buf 
 * @param {number} in_len 
 * @param {Buffer} out_buf 
 */
function decompressSlice(nodes, in_buf, in_len, out_buf) {
    const out_len = out_buf.byteLength;

    let currentCompressionLevel = 0;
    let bytesReadFromInput = 0;
    let repetitionCount = 0;
    let inOffset = 0;
    let outOffset = 0;
    let adjustedBytesToWrite = 0;

    // Process until we fill the output buffer
    for (let currentIndex = 0; currentIndex < out_len; currentIndex += adjustedBytesToWrite) {
        // Check if we've consumed all input
        if (bytesReadFromInput >= in_len) {
            console.error("huffRLE Error: bytesReadFromInput >= in_len");
            return 0;
        }

        // Read 4 bytes (DWORD) from input
        let initialByteValue = in_buf[inOffset] | (in_buf[inOffset + 1] << 8) |
            (in_buf[inOffset + 2] << 16) | (in_buf[inOffset + 3] << 24);
        initialByteValue = initialByteValue >>> 0;
        // Apply compression level shift if active
        if (currentCompressionLevel) {
            initialByteValue >>= currentCompressionLevel;
        }

        // Get the node for this byte value (3 bytes per node)
        const nodeOffset = (initialByteValue & 0xFF) * 3;
        const nodeFirstComponent = nodes[nodeOffset + 1];
        const nodeSecondComponent = nodes[nodeOffset + 2];
        const nodeThirdComponent = nodes[nodeOffset];

        let calculatedStride, finalStride;

        // Check if this is a terminal node (bit 7 of first component set)
        if (nodeFirstComponent & 0x80) {
            calculatedStride = nodeSecondComponent;
            finalStride = nodeThirdComponent | ((nodeFirstComponent & 0x7F) << 8);
        } else {
            // Non-terminal node - traverse the tree
            calculatedStride = nodeSecondComponent + 1;
            let centerIndex = nodeThirdComponent | ((nodeFirstComponent & 0x7F) << 8);
            let shiftAmount = 1 << nodeSecondComponent;
            let loopCounter = shiftAmount;
            let nextNodeValue, currentNodePointer;
            while (true) {
                shiftAmount = loopCounter;
                currentNodePointer = (centerIndex * 3) + ((loopCounter & initialByteValue) !== 0 ? 3 : 0);
                nextNodeValue = nodes[currentNodePointer + 1];

                if (nextNodeValue & 0x80) {
                    break;
                }

                centerIndex = ((nextNodeValue & 0x7F) << 8) | nodes[currentNodePointer];
                calculatedStride++;
                loopCounter *= 2;
            }

            finalStride = ((nextNodeValue & 0x7F) << 8) | nodes[currentNodePointer];
        }

        // Update compression level and input pointer
        const compressionStride = currentCompressionLevel + calculatedStride;
        currentCompressionLevel = compressionStride & 7;
        const bytesConsumed = compressionStride >> 3;
        inOffset += bytesConsumed;
        bytesReadFromInput += bytesConsumed;

        // Process the decoded operation type (bits 8-9 of finalStride)
        const operationType = finalStride & 0x300;

        adjustedBytesToWrite = 0;

        if (operationType === 0) {
            // Direct write
            out_buf[outOffset] = finalStride & 0xFF;
            adjustedBytesToWrite = 1;
        } else if (operationType === 0x100) {
            // Repeat count accumulation
            if (repetitionCount > 0xFF) {
                console.error("huffRLE Error: repetitionCount > 0xFF");
                return 0;
            }
            if (repetitionCount) {
                repetitionCount = (repetitionCount << 8) | (finalStride & 0xFF);
            } else {
                repetitionCount = finalStride & 0xFF;
            }
            adjustedBytesToWrite = 0;
        } else if (operationType === 0x200) {
            // Forward copy operation
            if (!repetitionCount) {
                repetitionCount = 1;
            }
            adjustedBytesToWrite = repetitionCount * (finalStride & 0xFF);

            if (currentIndex + adjustedBytesToWrite > out_len) {
                console.error("huffRLE Error: currentIndex + adjustedBytesToWrite > out_len");
                return 0;
            }

            const copyValue = finalStride & 0xFF;
            if (copyValue === 1) {
                // Copy 1 byte back repeatedly
                for (let i = 0; i < repetitionCount; i++) {
                    out_buf[outOffset + i] = out_buf[outOffset - 1];
                }
            } else if (copyValue === 2) {
                // Copy 2 bytes back repeatedly
                for (let i = 0; i < repetitionCount; i++) {
                    const copyIdx = (outOffset - 2) + (i * 2);
                    out_buf[outOffset + (i * 2)] = out_buf[copyIdx];
                    out_buf[outOffset + (i * 2) + 1] = out_buf[copyIdx + 1];
                }
            } else if (copyValue === 4) {
                // Copy 4 bytes back repeatedly
                for (let i = 0; i < repetitionCount; i++) {
                    const copyIdx = (outOffset - 4) + (i * 4);
                    out_buf[outOffset + (i * 4)] = out_buf[copyIdx];
                    out_buf[outOffset + (i * 4) + 1] = out_buf[copyIdx + 1];
                    out_buf[outOffset + (i * 4) + 2] = out_buf[copyIdx + 2];
                    out_buf[outOffset + (i * 4) + 3] = out_buf[copyIdx + 3];
                }
            }
            repetitionCount = 0;
        } else if (operationType === 0x300) {
            // Inverse copy operation
            adjustedBytesToWrite = finalStride & 0xFF;
            if (currentIndex + adjustedBytesToWrite > out_len) {
                console.error("huffRLE Error: currentIndex + adjustedBytesToWrite > out_len");
                return 0;
            }

            const totalBytesToProcess = repetitionCount + (finalStride & 0xFF);
            if (currentIndex < totalBytesToProcess) {
                console.error("huffRLE Error: currentIndex < totalBytesToProcess", currentIndex, totalBytesToProcess);
                return 0;
            }

            const inverseBuffer = outOffset - totalBytesToProcess;
            for (let i = 0; i < (finalStride & 0xFF); i++) {
                out_buf[outOffset + i] = out_buf[inverseBuffer + i];
            }
            repetitionCount = 0;
        } else {
            // Unknown operation type - just continue
            adjustedBytesToWrite = 0;
        }

        outOffset += adjustedBytesToWrite;
    }

    // Return success if input was completely consumed
    return bytesReadFromInput + (currentCompressionLevel !== 0 ? 1 : 0) === in_len;
};

module.exports = {
    decompressSlice
}