# TFHE_NN

This package contains the code to run the tests for the paper "Training Encrypted Neural Networks on Encrypted Data
with Fully Homomorphic Encryption".
All the code has been tested on a Linux machine, with Python 3.9; however, Python 3.8 should work too.

## Organization
- `pycrcnn`: source code for the TFHE-NNs definition and training;
- `HE_ML`: folder with the experiments. There are three subfolders containing the scripts and datasets for the three experiments considered:
  - `HE_ML/Exp1_EncryptedTraining/TernaryMNIST/`;
  - `HE_ML/Exp2_DistributedTraining/`, with the two folders for the "TernaryMNIST" experiment and the "FashionMNIST" one;
  - `HE_ML/Exp3_CrossValidation/`.
- `requirements.txt` contains the requirement needed to execute all the code.
- `nufhe` contains our fork of the nufhe Python library for executing the TFHE gates. After installing `requirements.txt`, also install the content of this folder in your environment.
  
## Experiments
### Exp1
In the Experiment 1 folder you can find `res`, which contains the weights of the model trained on encrypted data and the keys/DFA weights used (so that you can replicate the experiment if you want to).
The model was trained in the `Training.ipynb` notebook. It is already executed, so that you can check the cells' output, even though you can re-run that (consider that it will require some days). 
Nonetheless, you can use the `CheckResults.ipynb` notebook which compares the model trained on encrypted data with the same model learnt on plain data, with some considerations on the weights' values etc.

### Exp 2
In the Experiment 2 folder you will find the two subfolders for the two used datasets.
`TernaryMNIST` is very similar to Exp 1, even though you will find two `TrainingModelX.ipynb` notebooks, one for each model, and the `Aggregation.ipynb` one, which outputs the aggregated encrypted model starting from Model1 and Model2. In the `CheckResults.ipynb` notebook you will see the numerical values presented in the paper.
`FashionMNIST` is a bit different because this experiment has not been run on encrypted data (as specified in the paper). You will find the notebook `TrainingSingleModel.ipynb`, to check the accuracy of the model trained on the whole training set, and the `TrainingMultipleModels.ipynb` to see how the models are aggregated. `Results.ipynb` presents the numerical results shown in the paper, along with additional plots and statistics.

### Exp 3
In the Experiment 3 folder you will find the notebooks used to train the four models (i.e., `TrainingModelX.ipynb`), along with the `CrossValidation.ipynb` notebook which shows the actual encrypted cross-validation procedure able to process encrypted models.

