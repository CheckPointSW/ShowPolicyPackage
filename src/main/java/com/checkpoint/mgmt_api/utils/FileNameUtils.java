package com.checkpoint.mgmt_api.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for filename sanitization to prevent "File name too long" filesystem errors.
 * Provides cross-platform compatible filename handling with length limits and character filtering.
 */
public class FileNameUtils {
    
    // Maximum filename length (excluding path and extension) to ensure compatibility across filesystems
    // Linux supports up to 255, Windows up to 260, but we use a conservative limit for safety
    private static final int MAX_FILENAME_LENGTH = 200;
    // Maximum length for the truncated portion before adding hash
    private static final int MAX_TRUNCATED_LENGTH = 150;
    
    /**
     * Sanitizes a filename to ensure it doesn't exceed filesystem limits.
     * If the filename is too long, it truncates the name and adds a hash suffix for uniqueness.
     * 
     * This method handles cross-platform filename restrictions:
     * - Removes/replaces invalid characters for both Windows and Linux
     * - Enforces length limits compatible with most filesystems
     *
     * @param baseFileName the original filename (without extension)
     * @return sanitized filename that fits within filesystem limits
     */
    public static String sanitizeFileName(String baseFileName) {
        if (baseFileName == null || baseFileName.isEmpty()) {
            return "unnamed";
        }
        
        // Remove or replace invalid filename characters for cross-platform compatibility
        // Linux is more permissive, but we sanitize for Windows compatibility as well
        String sanitized = baseFileName
            .replaceAll("[<>:\"/\\\\|?*]", "_")  // Windows invalid chars
            .replaceAll("\\s+", "_")             // Replace multiple spaces with single underscore
            .replaceAll("_{2,}", "_")            // Replace multiple underscores with single
            .replaceAll("^[._]+", "")            // Remove leading dots/underscores (Linux hidden files)
            .replaceAll("[._]+$", "");           // Remove trailing dots/underscores
        
        // Ensure we have a valid filename after sanitization
        if (sanitized.isEmpty()) {
            sanitized = "unnamed";
        }
        
        // Check if filename length is within limits
        if (sanitized.length() <= MAX_FILENAME_LENGTH) {
            return sanitized;
        }
          // Filename is too long, need to truncate and add hash for uniqueness
        String truncated = sanitized.substring(0, Math.min(sanitized.length(), MAX_TRUNCATED_LENGTH));
        String hash = generateShortHash(baseFileName);  // Use original name for hash to maintain uniqueness
        String result = truncated + "_" + hash;        // Log the truncation for debugging purposes
        System.out.println("WARNING: Filename too long, truncated from '" + baseFileName + "' to '" + result + "'");
        
        return result;
    }
    
    /**
     * Generates a short hash from the input string to ensure filename uniqueness.
     *
     * @param input the string to hash
     * @return a short hash string (8 characters)
     */
    public static String generateShortHash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            
            // Convert to hex and take first 8 characters for a short unique identifier
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(4, hash.length); i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // Fallback: use hashCode if MD5 is not available
            return String.format("%08x", Math.abs(input.hashCode()));
        }
    }
}
