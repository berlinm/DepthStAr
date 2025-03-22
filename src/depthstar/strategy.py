from depthstar.logger import Logger
from abc import ABC, abstractmethod
import math, reprlib

class StrategyFactory:
    """Factory for creating function prioritization strategies based on user input."""
    logger = Logger()
    @staticmethod
    def bake_strategy(strategy_name, exceptions={}):
        """Creates a strategy instance based on the provided name."""
        strategies = {
            "LEFM": LeastExploredFromMain,
            "MEFM": MostExploredFromMain
        }
        if strategy_name in strategies:
            StrategyFactory.logger.info(f"Using strategy '{strategy_name}'")
            return strategies[strategy_name](exceptions)
        else:
            StrategyFactory.logger.critical(f"Unknown strategy '{strategy_name}'. Available strategies: {list(strategies.keys())}")
            raise ValueError(f"Unknown strategy '{strategy_name}'. Available strategies: {list(strategies.keys())}")


class Strategy(ABC):
    """Abstract base class for function prioritization heuristics."""

    def __init__(self, exceptions={}):
        self.exceptions = exceptions
        self.logger = Logger()
        self.logger.info(f"Strategy '{self.get_strategy_name()}' initialized with exceptions: {exceptions}")

    def get_function_score(self, function_execution_data, function_name):
        """
        Checks if the function is an exception and returns the score if it is, otherwise calls the
        abstract method _get_function_score to calculate the score.
        """
        if function_name in self.exceptions:
            return self.exceptions[function_name]
        return self._get_function_score(function_execution_data, function_name)
    @abstractmethod
    def _get_function_score(self, function_execution_data, function_name):
        """Calculates a relative score for a function based on its execution data.
    
        The score is normalized between 1 and 5, with logarithmic scaling applied to smooth
        differences between similar values. A linear boost is applied if there is a significant
        gap between the maximum score and the second-highest score.
        """
        pass

    @abstractmethod
    def get_strategy_name(self):
        """Returns the name of the strategy."""
        pass
        

class LeastExploredFromMain(Strategy):
    def _get_function_score(self, function_execution_data, function_name):
        """Calculates a relative score for a function based on its execution data.
        The method normalizes the function's execution count, applies logarithmic scaling,
        and adjusts the score with a linear boost if there is a significant gap between
        the highest and second-highest execution counts.
        """
        # Placeholder implementation
        return 1  # Replace with actual logic as needed
    
    def get_strategy_name(self):
        """Returns the name of the strategy."""
        return "LEFM"

class MostExploredFromMain(Strategy):
    def _get_function_score(self, function_execution_data, function_name):
        """
        Calculate and return the score for a given function based on its execution data.

        Args:
            function_execution_data (dict): A dictionary containing execution data for various functions.
            function_name (str): The name of the function for which the score is to be calculated.

        Returns:
            float: The calculated score for the specified function.

        Raises:
            KeyError: If the function_name is not found in the function_execution_data.
            ValueError: If the execution data for the function is invalid or incomplete.
        """
        scores = function_execution_data.values()
        # Get the execution count for the function at the given index
        function_score = function_execution_data[function_name]
        
        # Get the minimum and maximum values of the scores
        min_score = min(scores)
        max_score = max(scores)
        
        # Handle the case where min_score == max_score to avoid division by zero
        if max_score == min_score:
            return 5  # If all scores are the same, return the max score (5)
        
        # Normalize the score between 0 and 1
        normalized_score = (function_score - min_score) / (max_score - min_score)
        
        # Apply logarithmic scaling to smooth the difference between similar values
        smoothing_factor = math.log(normalized_score + 1)  # log(x + 1) to avoid log(0)
        
        # Linear boost if there is a significant gap between max_score and the next non-zero score
        second_max_score = sorted(set(scores), reverse=True)[1]  # Second highest non-zero score
        if max_score > second_max_score * 1.5:  # If the difference is significant
            relative_score = 1 + (4 * normalized_score)  # Boost the score more linearly
        else:
            # Scale to the range [1, 5]
            relative_score = 1 + 4 * smoothing_factor
        
        self.logger.debug(f"Calculating score for function '{function_name}': execution data: {scores} ({function_score}), function score: {round(relative_score)}")
        return round(relative_score)
    
    def get_strategy_name(self):
        """Returns the name of the strategy."""
        return "MEFM"