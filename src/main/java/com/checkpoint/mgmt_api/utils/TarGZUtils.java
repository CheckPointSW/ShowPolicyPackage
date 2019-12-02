package com.checkpoint.mgmt_api.utils;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.utils.IOUtils;

import java.io.*;

/**
 * This class creates the tar.gz file, containing all of the html and json files.
 */
public class TarGZUtils
{
    public static void createTarGZ(String dirPath, String tarGzPath, boolean deleteTempDir) throws IOException {

        try (
                OutputStream fOut  = new FileOutputStream(new File(tarGzPath));
                OutputStream bOut  = new BufferedOutputStream(fOut);
                OutputStream gzOut = new GzipCompressorOutputStream(bOut);
                TarArchiveOutputStream tOut  = new TarArchiveOutputStream(gzOut)
        )
        {
            tOut.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
            File f = new File(dirPath);
            if (f.isDirectory()) {
                //pass over all the files in the directory
                File[] children = f.listFiles();
                if (children != null) {
                    for (File child : children) {
                        addFileToTarGz(tOut, child);
                    }
                }
                if(deleteTempDir) {
                    deleteTempFolder(dirPath);
                }
            } else {
                System.out.println("The given directory path is not a directory");
            }
        }
    }

    /**
     * This function copies a given file to the zip file
     *
     * @param tarArchiveOutputStream tar output stream of the zip file
     * @param file the file to insert to the zar file
     *
     * @throws IOException
     */
    private static void addFileToTarGz(TarArchiveOutputStream tarArchiveOutputStream, File file)
                                            throws IOException
    {
        String entryName =  file.getName();
        TarArchiveEntry tarEntry = new TarArchiveEntry(file, entryName);
        tarArchiveOutputStream.putArchiveEntry(tarEntry);

        if (file.isFile()) {

            try (FileInputStream input = new FileInputStream(file))
            {
                IOUtils.copy(input, tarArchiveOutputStream);
            }
            tarArchiveOutputStream.closeArchiveEntry();
        } else {//Directory
            System.out.println("The directory which need to be packed to tar folder cannot contain other directories");
        }
    }


    /**
     * This function delete a given directory.
     *
     * @param dirPath the directory path
     */
    private static void deleteTempFolder(String dirPath){

        File f = new File(dirPath);
        if (f.isDirectory()) {
            //pass over all the files in the directory
            File[] children = f.listFiles();
            if (children != null) {
                for (File child : children) {
                    child.delete();
                }
            }
        } else {
            System.out.println("The given directury path is not a directory");
        }

        f.delete();
    }
}
