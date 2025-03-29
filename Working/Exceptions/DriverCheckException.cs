namespace WindowsDriverInfo.Exceptions;

public class DriverCheckException : Exception
{
    public string DriverPath { get; }
    
    public DriverCheckException(string message, string driverPath) 
        : base(message)
    {
        DriverPath = driverPath;
    }
}
