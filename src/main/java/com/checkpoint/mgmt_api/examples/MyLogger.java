package com.checkpoint.mgmt_api.examples;

import java.util.MissingResourceException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class adds Level debug (which is smaller then info)
 */
class MyLevel extends Level {

    public static final Level DEBUG = new MyLevel("DEBUG", 750);

    public MyLevel(String name, int value)
    {
        super(name, value);
    }
}

/**
 * This class extend {@link Logger} to contain debug level.
 * Also this class saves the worse debug level that the logger used during the run of the tool. (Needed for exit code only)
 */
class MyLogger extends Logger
{


    static int SEVERE_CODE = 3;
    static int WARNING_CODE = 2;
    static int SUCCESS_CODE = 0;

    private int mostSevereLevel = SUCCESS_CODE;

    /**
     * Protected method to construct a logger for a named subsystem.
     * <p/>
     * The logger will be initially configured with a null Level
     * and with useParentHandlers set to true.
     *
     * @param name               A name for the logger.  This should
     *                           be a dot-separated name and should normally
     *                           be based on the package name or class name
     *                           of the subsystem, such as java.net
     *                           or javax.swing.  It may be null for anonymous Loggers.
     * @param resourceBundleName name of ResourceBundle to be used for localizing
     *                           messages for this logger.  May be null if none
     *                           of the messages require localization.
     * @throws MissingResourceException if the resourceBundleName is non-null and
     *                                  no corresponding resource can be found.
     */
    protected MyLogger(String name, String resourceBundleName)
    {
        super(name, resourceBundleName);
    }

    public void debug(String message){
        super.log(MyLevel.DEBUG, message);
    }

    @Override
    public void severe(String message){
        super.severe(message);
        if (mostSevereLevel < SEVERE_CODE) {
            this.mostSevereLevel = SEVERE_CODE;
        }
    }

    @Override
    public void warning(String message){
        super.warning(message);
        if (mostSevereLevel < WARNING_CODE) {
            this.mostSevereLevel = WARNING_CODE;
        }
    }

    @Override
    public void setLevel(Level newLevel) throws SecurityException
    {
        super.setLevel(newLevel);
    }

    int getMostSevereLevel( ){
        return mostSevereLevel;
    }
}
