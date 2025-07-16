import datetime
import logging
import azure.functions as func
import sys
import os
import json
import traceback

# Configure structured logging for Azure Functions
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add the parent directory to Python path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mainv3

def main(mytimer: func.TimerRequest) -> None:
    """
    Azure Function entry point for CVE processing
    Triggered by timer schedule (every 5 minutes by default)
    """
    logger = logging.getLogger('CVEProcessor')
    
    # Create execution context for logging
    execution_id = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    # Log function start with context
    logger.info(json.dumps({
        'event': 'function_start',
        'execution_id': execution_id,
        'timestamp': utc_timestamp,
        'trigger_type': 'timer',
        'past_due': mytimer.past_due if mytimer else False
    }))

    if mytimer and mytimer.past_due:
        logger.warning(json.dumps({
            'event': 'timer_past_due',
            'execution_id': execution_id,
            'timestamp': utc_timestamp,
            'message': 'Timer trigger is past due - may indicate performance issues'
        }))

    # Track processing metrics
    start_time = datetime.datetime.utcnow()
    processing_result = {
        'execution_id': execution_id,
        'start_time': start_time.isoformat(),
        'success': False,
        'error': None,
        'duration_seconds': 0,
        'cves_processed': 0
    }
    
    try:
        logger.info(json.dumps({
            'event': 'cvs_processing_start',
            'execution_id': execution_id,
            'timestamp': utc_timestamp
        }))
        
        # Run the CVE polling process
        success = mainv3.poll_nvd()
        
        # Calculate processing duration
        end_time = datetime.datetime.utcnow()
        processing_result['duration_seconds'] = (end_time - start_time).total_seconds()
        processing_result['end_time'] = end_time.isoformat()
        processing_result['success'] = success
        
        if success:
            logger.info(json.dumps({
                'event': 'cvs_processing_success',
                'execution_id': execution_id,
                'duration_seconds': processing_result['duration_seconds'],
                'timestamp': end_time.isoformat()
            }))
        else:
            logger.error(json.dumps({
                'event': 'cvs_processing_failed',
                'execution_id': execution_id,
                'duration_seconds': processing_result['duration_seconds'],
                'timestamp': end_time.isoformat(),
                'message': 'CVE processing returned failure status'
            }))
            
    except Exception as e:
        end_time = datetime.datetime.utcnow()
        processing_result['duration_seconds'] = (end_time - start_time).total_seconds()
        processing_result['end_time'] = end_time.isoformat()
        processing_result['error'] = str(e)
        
        # Log detailed error information
        logger.error(json.dumps({
            'event': 'cvs_processing_exception',
            'execution_id': execution_id,
            'duration_seconds': processing_result['duration_seconds'],
            'timestamp': end_time.isoformat(),
            'error_message': str(e),
            'error_type': type(e).__name__,
            'traceback': traceback.format_exc()
        }))
        
        # Re-raise exception to ensure proper Azure Functions error handling
        raise
    
    finally:
        # Log final execution summary
        logger.info(json.dumps({
            'event': 'function_end',
            'execution_summary': processing_result
        }))
        
        # Log performance metrics for monitoring
        if processing_result['duration_seconds'] > 300:  # 5 minutes
            logger.warning(json.dumps({
                'event': 'performance_warning',
                'execution_id': execution_id,
                'duration_seconds': processing_result['duration_seconds'],
                'message': 'Function execution took longer than expected (>5min)'
            }))