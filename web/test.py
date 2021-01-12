def func(x,c=None, y=None, z=None):
    print(x,c,y,z)
a={
    "y": 12,
    "z": 11
}
func(10,**a)