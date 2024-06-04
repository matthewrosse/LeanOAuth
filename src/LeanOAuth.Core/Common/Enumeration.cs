using System.Reflection;

namespace LeanOAuth.Core.Common;

public abstract class Enumeration<TEnum> : IEquatable<Enumeration<TEnum>>
    where TEnum : Enumeration<TEnum>
{
    private static readonly Dictionary<int, TEnum> Enumerations = CreateEnumerations();
    public int Value { get; }
    public string Name { get; }

    protected Enumeration(int value, string name)
    {
        Value = value;
        Name = name;
    }

    public static TEnum? FromValue(int value) => Enumerations.GetValueOrDefault(value);

    public static TEnum? FromName(string name) =>
        Enumerations.Values.SingleOrDefault(e => e.Name == name);

    public bool Equals(Enumeration<TEnum>? other)
    {
        if (other is null)
        {
            return false;
        }

        return GetType() == other.GetType() && Value == other.Value;
    }

    public override bool Equals(object? obj) => obj is Enumeration<TEnum> other && Equals(other);

    public static bool operator ==(Enumeration<TEnum> left, Enumeration<TEnum> right) =>
        left.Equals(right);

    public static bool operator !=(Enumeration<TEnum> left, Enumeration<TEnum> right) =>
        !left.Equals(right);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Name;

    private static Dictionary<int, TEnum> CreateEnumerations()
    {
        var enumerationType = typeof(TEnum);

        var fieldForType = enumerationType
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(fieldInfo => enumerationType.IsAssignableFrom(fieldInfo.FieldType))
            .Select(fieldInfo => (TEnum)fieldInfo.GetValue(default)!);

        return fieldForType.ToDictionary(x => x.Value);
    }
}
