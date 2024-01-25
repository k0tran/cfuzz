class TemperatureConverter {
public:
    TemperatureConverter() = delete;

    static double celsius_to_fahrenheit(double celsius) {
        return (celsius * 9 / 5) + 32;
    }

    static double fahrenheit_to_celsius(double fahrenheit) {
        return (fahrenheit - 32) * 5 / 9;
    }
};
