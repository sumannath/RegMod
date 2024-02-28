using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RegMod
{
    internal class Policy
    {
        public string PolicyUID { get; set; }
        public string Path { get; set; }
        public string Entry { get; set; }
        public string Value { get; set; }
        public string RegType { get; set; }
        public string OperatingSystem { get; set; }
    }
}
