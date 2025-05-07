from setuptools import setup, find_packages
setup(
    name="SignerPy",
    version="0.1",
    author="L7N",
    author_email="l7ng4q@gmail.com",
    description="SignerPy For TikTok",
    packages=find_packages(),
    install_requires=[
        "user_agent",
        "requests",
        "pycryptodome"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)