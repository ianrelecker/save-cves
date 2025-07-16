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

def log_custom_event(logger, event_name: str, properties: dict = None, measurements: dict = None):
    """
    Log custom events that will appear in Application Insights customEvents table
    """
    event_data = {
        'event_name': event_name,
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'properties': properties or {},
        'measurements': measurements or {}
    }
    
    # Log with structured format for Application Insights
    logger.info(f"CUSTOM_EVENT: {event_name}", extra={
        'custom_dimensions': {
            'event_name': event_name,
            'event_data': json.dumps(event_data),
            **event_data['properties']
        }
    })

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
    log_custom_event(logger, 'function_start', {
        'execution_id': execution_id,
        'trigger_type': 'timer',
        'past_due': str(mytimer.past_due if mytimer else False)
    })

    if mytimer and mytimer.past_due:
        log_custom_event(logger, 'timer_past_due', {
            'execution_id': execution_id,
            'message': 'Timer trigger is past due - may indicate performance issues'
        })

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
        log_custom_event(logger, 'cve_processing_start', {
            'execution_id': execution_id
        })
        
        # Run the CVE polling process
        success = mainv3.poll_nvd()
        
        # Calculate processing duration
        end_time = datetime.datetime.utcnow()
        processing_result['duration_seconds'] = (end_time - start_time).total_seconds()
        processing_result['end_time'] = end_time.isoformat()
        processing_result['success'] = success
        
        if success:
            log_custom_event(logger, 'cve_processing_success', {
                'execution_id': execution_id,
                'status': 'success'
            }, {
                'duration_seconds': processing_result['duration_seconds']
            })
        else:
            log_custom_event(logger, 'cve_processing_failed', {
                'execution_id': execution_id,
                'status': 'failed',
                'message': 'CVE processing returned failure status'
            }, {
                'duration_seconds': processing_result['duration_seconds']
            })
            
    except Exception as e:
        end_time = datetime.datetime.utcnow()
        processing_result['duration_seconds'] = (end_time - start_time).total_seconds()
        processing_result['end_time'] = end_time.isoformat()
        processing_result['error'] = str(e)
        
        # Log detailed error information
        log_custom_event(logger, 'cve_processing_exception', {
            'execution_id': execution_id,
            'error_message': str(e),
            'error_type': type(e).__name__,
            'traceback': traceback.format_exc()
        }, {
            'duration_seconds': processing_result['duration_seconds']
        })
        
        # Re-raise exception to ensure proper Azure Functions error handling
        raise
    
    finally:
        # Log final execution summary
        log_custom_event(logger, 'function_end', {
            'execution_id': execution_id,
            'final_status': 'success' if processing_result['success'] else 'failed',
            'has_error': str(bool(processing_result.get('error')))
        }, {
            'duration_seconds': processing_result['duration_seconds'],
            'cves_processed': processing_result['cves_processed']
        })
        
        # Log performance metrics for monitoring
        if processing_result['duration_seconds'] > 300:  # 5 minutes
            log_custom_event(logger, 'performance_warning', {
                'execution_id': execution_id,
                'message': 'Function execution took longer than expected (>5min)'
            }, {
                'duration_seconds': processing_result['duration_seconds']
            })