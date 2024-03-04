using Newtonsoft.Json.Serialization;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace EmbedIO
{
    [System.AttributeUsage(System.AttributeTargets.Property, AllowMultiple = false)]
    public class GetOnlyJsonPropertyAttribute : Attribute
    {
    }

    public class GetOnlyContractResolver : DefaultContractResolver
    {
        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            var property = base.CreateProperty(member, memberSerialization);
            if (property != null && property.Writable)
            {
                var attributes = property.AttributeProvider.GetAttributes(typeof(GetOnlyJsonPropertyAttribute), true);
                if (attributes != null && attributes.Count > 0)
                    property.Writable = false;
            }
            return property;
        }
    }
}
